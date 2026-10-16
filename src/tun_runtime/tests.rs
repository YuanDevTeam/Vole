use std::{
    future::Future as _,
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    os::unix::net::UnixDatagram,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

use async_trait::async_trait;
use tokio::{
    io::AsyncReadExt as _,
    sync::{Notify, mpsc},
};

use super::*;
use crate::{
    config::{
        DnsConfig, DnsNameserver, DnsRoute, DnsTransport, PortRange, RuleAction, RuleKind,
        RuleSpec, SnifferConfig,
    },
    dispatch::{BoxStream, DatagramTransport},
    dns::{QueryType, build_query, synthesize_empty_response},
    platform::TunFd,
    routing::{EmptyGeoMatcher, ProxyDispatchers, RuleSet},
};

fn test_tun_config() -> TunConfig {
    TunConfig {
        mtu: 1500,
        udp_timeout: Duration::from_secs(30),
        ..TunConfig::default()
    }
}

fn test_sniffer(
    http_ports: &[PortRange],
    tls_ports: &[PortRange],
    quic_ports: &[PortRange],
) -> Arc<SnifferConfig> {
    Arc::new(SnifferConfig {
        enable: true,
        http_ports: http_ports.into(),
        tls_ports: tls_ports.into(),
        quic_ports: quic_ports.into(),
        http_override: false,
        tls_override: false,
        quic_override: false,
        ..SnifferConfig::disabled()
    })
}

#[test]
fn tun_netstack_resource_event_contract_is_stable() {
    assert_eq!(TUN_NETSTACK_STATS_INTERVAL, Duration::from_secs(30));
    assert_eq!(
        TUN_NETSTACK_STATS_PERIODIC_EVENT,
        "tun_netstack_stats_periodic"
    );
    assert_eq!(TUN_NETSTACK_STATS_FINAL_EVENT, "tun_netstack_stats_final");
}

#[test]
fn ipv6_ingress_policy_drops_only_ipv6_when_disabled() {
    assert!(!tun_ingress_allowed(false, &[0x60]));
    assert!(tun_ingress_allowed(false, &[0x45]));
    assert!(tun_ingress_allowed(false, &[]));
    assert!(tun_ingress_allowed(true, &[0x60]));
}

#[tokio::test]
async fn batch_tun_runtime_preserves_order_stats_and_invalid_packet_isolation() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let tun = TunIo::new(
        TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
        crate::TunFraming::RawIp,
    )
    .unwrap();
    let source = "192.0.2.10:12000".parse().unwrap();
    let destination = "198.51.100.20:443".parse().unwrap();
    let mut bytes = 0;
    // Nine queued frames cross the batch boundary. The invalid middle
    // frame must not hide its neighbours, and IPv6 policy stays per packet.
    for index in 0..7 {
        let packet = build_udp(source, destination, &[index]);
        bytes += packet.len();
        peer.send(&packet).unwrap();
        if index == 2 {
            peer.send(&[0x70]).unwrap();
            peer.send(&[0x60; 40]).unwrap();
        }
    }
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let stats = Arc::new(TunTrafficStats::default());
    let runtime = TunRuntime::new_with_stats(
        tun,
        ResourceLimits::default(),
        &test_tun_config(),
        dispatcher.clone(),
        None,
        false,
        false,
        None,
        stats.clone(),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));
    let mut response = [0; TUN_MTU];
    for index in 0..7 {
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_udp_response(&response[..size], destination, source, &[index]);
    }
    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stats.snapshot().up_total, (bytes + 40) as u64);
    assert_eq!(stats.snapshot().down_total, bytes as u64);
    assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert!(peer.try_recv(&mut response).is_err(), "packet replayed");
}

#[tokio::test]
async fn batch_tun_read_loop_counts_consumed_prefix_before_eof() {
    use std::{io::Write as _, os::unix::net::UnixStream};

    let (host, mut peer) = UnixStream::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    let tun = TunIo::new(
        TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
        crate::TunFraming::RawIp,
    )
    .unwrap();
    let packet = build_udp(
        "192.0.2.10:12000".parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
        b"prefix",
    );
    peer.write_all(&packet).unwrap();
    drop(peer);
    let stats = Arc::new(TunTrafficStats::default());
    let runtime = TunRuntime::new_with_stats(
        tun,
        ResourceLimits::default(),
        &test_tun_config(),
        Arc::new(MockDispatcher::default()),
        None,
        true,
        false,
        None,
        stats.clone(),
    )
    .unwrap();
    let error = timeout(
        Duration::from_secs(2),
        runtime.run(CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(stats.snapshot().up_total, packet.len() as u64);
}

#[tokio::test]
async fn effective_mtu_drops_oversized_udp_before_association_and_keeps_neighbor_responsive() {
    assert_effective_mtu_drops_oversized_udp(false).await;
}

#[tokio::test]
async fn effective_mtu_drops_oversized_dns_before_query_and_keeps_neighbor_responsive() {
    assert_effective_mtu_drops_oversized_udp(true).await;
}

async fn assert_effective_mtu_drops_oversized_udp(dns_query: bool) {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let tun = TunIo::new(
        TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
        crate::TunFraming::RawIp,
    )
    .unwrap();
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let neighbor_source: SocketAddr = "192.0.2.10:12001".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let oversized_destination = if dns_query {
        "198.51.100.20:53".parse().unwrap()
    } else {
        destination
    };
    let oversized_payload = if dns_query {
        let mut query = build_query(0x1234, "oversized.example", QueryType::A).unwrap();
        query[10..12].copy_from_slice(&1_u16.to_be_bytes());
        // A legal EDNS OPT record with padding makes a 1373-byte DNS query,
        // not trailing garbage that the DNS parser would already reject.
        let option_data_len = 1373 - query.len() - 11;
        query.push(0);
        query.extend_from_slice(&41_u16.to_be_bytes());
        query.extend_from_slice(&1232_u16.to_be_bytes());
        query.extend_from_slice(&0_u32.to_be_bytes());
        query.extend_from_slice(&u16::try_from(option_data_len).unwrap().to_be_bytes());
        query.extend_from_slice(&12_u16.to_be_bytes());
        query.extend_from_slice(&u16::try_from(option_data_len - 4).unwrap().to_be_bytes());
        query.resize(1373, 0);
        classify_query(&query).expect("oversized DNS fixture must be structurally valid");
        query
    } else {
        vec![0x5a; 1373]
    };
    let oversized = build_udp(source, oversized_destination, &oversized_payload);
    assert_eq!(oversized.len(), 1401);
    let neighbor = build_udp(neighbor_source, destination, b"neighbor");
    peer.send(&oversized).unwrap();
    peer.send(&neighbor).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let dns_dispatcher = Arc::new(DnsReplyDispatcher::default());
    let stats = Arc::new(TunTrafficStats::default());
    let runtime = TunRuntime::new_with_stats(
        tun,
        ResourceLimits {
            tun_max_datagram_size: 1400,
            ..ResourceLimits::default()
        },
        &TunConfig {
            mtu: 1400,
            ..test_tun_config()
        },
        dispatcher.clone(),
        dns_query.then(|| test_runtime_dns(dns_dispatcher.clone())),
        true,
        false,
        None,
        stats.clone(),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let probe = observation::ResourceProbe::default();
    let task_probe = probe.clone();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move { task_probe.scope(runtime.run(task_cancellation)).await });
    let mut response = [0_u8; TUN_MTU];
    let received = timeout(Duration::from_secs(2), async {
        loop {
            let size = peer.recv(&mut response).await.unwrap();
            if u16::from_be_bytes(response[22..24].try_into().unwrap()) == neighbor_source.port() {
                assert_udp_response(&response[..size], destination, neighbor_source, b"neighbor");
                return size;
            }
        }
    })
    .await;
    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("MTU rejection prevented the TUN stop barrier")
        .unwrap()
        .unwrap();
    let neighbor_size = received.expect("oversized ingress hid its legal neighbor");
    let observed = probe.snapshot();
    assert!(observed.is_idle(), "TUN stop retained a child resource");
    assert_eq!(observed.peak(observation::ResourceKind::Association), 1);
    assert_eq!(observed.peak(observation::ResourceKind::Waiter), 0);
    assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert_eq!(
        dispatcher.udp_sessions.lock().unwrap()[0].source,
        neighbor_source
    );
    assert!(dns_dispatcher.udp_sessions.lock().unwrap().is_empty());
    assert_eq!(
        stats.snapshot().up_total,
        (oversized.len() + neighbor.len()) as u64
    );
    assert_eq!(stats.snapshot().down_total, neighbor_size as u64);
    assert!(
        peer.try_recv(&mut response).is_err(),
        "oversized response escaped"
    );
}

#[test]
fn configured_sniffer_selects_custom_http_and_tls_ports() {
    let config = test_sniffer(
        &[PortRange {
            start: 8_080,
            end: 8_088,
        }],
        &[PortRange {
            start: 8_443,
            end: 8_443,
        }],
        &[],
    );
    assert_eq!(
        configured_sniff_protocol(&config, 8_084),
        Some(SniffProtocol::Http)
    );
    assert_eq!(
        configured_sniff_protocol(&config, 8_443),
        Some(SniffProtocol::Tls)
    );
    assert_eq!(configured_sniff_protocol(&config, 80), None);
    assert_eq!(configured_sniff_protocol(&config, 443), None);
}

struct ScriptedQuicSniffer {
    outcomes: VecDeque<QuicSniffOutcome>,
    authentications: VecDeque<bool>,
    authenticated_initial_in_last_ingest: bool,
}

impl QuicSniffEngine for ScriptedQuicSniffer {
    fn ingest(&mut self, _packet: &[u8]) -> QuicSniffOutcome {
        self.authenticated_initial_in_last_ingest =
            self.authentications.pop_front().unwrap_or(true);
        self.outcomes
            .pop_front()
            .expect("scripted QUIC sniffer outcome exhausted")
    }

    fn authenticated_initial_in_last_ingest(&self) -> bool {
        self.authenticated_initial_in_last_ingest
    }
}

fn scripted_quic_state(
    scripts: Vec<Vec<QuicSniffOutcome>>,
) -> UdpQuicSniffState<ScriptedQuicSniffer, impl FnMut() -> ScriptedQuicSniffer> {
    let mut scripts = scripts
        .into_iter()
        .map(VecDeque::from)
        .collect::<VecDeque<_>>();
    UdpQuicSniffState::with_idle_timeout(
        move || ScriptedQuicSniffer {
            outcomes: scripts
                .pop_front()
                .expect("scripted QUIC flow factory exhausted"),
            authentications: VecDeque::new(),
            authenticated_initial_in_last_ingest: false,
        },
        Duration::from_secs(30),
    )
}

fn scripted_quic_state_with_authentication(
    scripts: Vec<Vec<(QuicSniffOutcome, bool)>>,
) -> UdpQuicSniffState<ScriptedQuicSniffer, impl FnMut() -> ScriptedQuicSniffer> {
    let mut sniffers = scripts
        .into_iter()
        .map(|script| {
            let (outcomes, authentications) = script.into_iter().unzip();
            ScriptedQuicSniffer {
                outcomes,
                authentications,
                authenticated_initial_in_last_ingest: false,
            }
        })
        .collect::<VecDeque<_>>();
    UdpQuicSniffState::with_idle_timeout(
        move || {
            sniffers
                .pop_front()
                .expect("scripted QUIC flow factory exhausted")
        },
        Duration::from_secs(30),
    )
}

fn test_udp_datagram(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &'static [u8],
) -> UdpDatagram {
    UdpDatagram::new(source, destination, Bytes::from_static(payload))
}

fn quic_connection_marker(destination_connection_id: &[u8]) -> Bytes {
    assert!((1..=20).contains(&destination_connection_id.len()));
    let mut datagram = vec![
        0xc0, // QUIC v1 long header, Initial packet.
        0x00,
        0x00,
        0x00,
        0x01,
        u8::try_from(destination_connection_id.len()).unwrap(),
    ];
    datagram.extend_from_slice(destination_connection_id);
    datagram.extend_from_slice(&[
        0x00, // Empty source connection ID.
        0x00, // Empty token.
        0x11, // One packet-number byte plus a 16-byte AEAD tag.
    ]);
    datagram.extend_from_slice(&[0; 17]);
    let datagram = Bytes::from(datagram);
    assert!(quic_connection_key(&datagram).is_some());
    datagram
}

fn quic_non_initial_marker(packet_type: u8, destination_connection_id: &[u8]) -> Bytes {
    assert!((1..=3).contains(&packet_type));
    assert!((1..=20).contains(&destination_connection_id.len()));
    let mut datagram = vec![
        0xc0 | (packet_type << 4),
        0x00,
        0x00,
        0x00,
        0x01,
        u8::try_from(destination_connection_id.len()).unwrap(),
    ];
    datagram.extend_from_slice(destination_connection_id);
    datagram.extend_from_slice(&[
        0x00, // Empty source connection ID.
        0x11, // Protected payload length.
    ]);
    datagram.extend_from_slice(&[0; 17]);
    let datagram = Bytes::from(datagram);
    assert!(quic_connection_key(&datagram).is_none());
    assert!(!quic_has_unsupported_version(&datagram));
    datagram
}

fn unsupported_quic_version_marker(destination_connection_id: &[u8]) -> Bytes {
    assert!((1..=20).contains(&destination_connection_id.len()));
    let mut datagram = vec![
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        u8::try_from(destination_connection_id.len()).unwrap(),
    ];
    datagram.extend_from_slice(destination_connection_id);
    let datagram = Bytes::from(datagram);
    assert!(quic_connection_key(&datagram).is_none());
    assert!(quic_has_unsupported_version(&datagram));
    datagram
}

#[test]
fn quic_fragmentation_sends_nothing_early_then_replays_every_datagram_in_order() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![vec![
        QuicSniffOutcome::NeedMoreData,
        QuicSniffOutcome::Matched("api.example.com".to_owned()),
    ]]);

    assert!(matches!(
        state.ingest_datagram(test_udp_datagram(source, destination, b"initial-one"), now,),
        QuicIngressResult::Buffered
    ));
    assert_eq!(state.pending_datagrams, 1);
    assert_eq!(state.pending_bytes, b"initial-one".len());

    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        test_udp_datagram(source, destination, b"initial-two"),
        now + Duration::from_millis(1),
    ) else {
        panic!("the completed ClientHello must release the buffered Initial flight");
    };
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
    assert_eq!(
        replay
            .iter()
            .map(|prepared| prepared.datagram.payload.as_ref())
            .collect::<Vec<_>>(),
        vec![b"initial-one".as_slice(), b"initial-two".as_slice()]
    );
    assert!(replay.iter().all(|prepared| {
        prepared.sniffed_domain.as_deref() == Some("api.example.com")
            && prepared.datagram.destination == destination
    }));

    let QuicIngressResult::Forward(next) = state.ingest_datagram(
        test_udp_datagram(source, destination, b"short-header"),
        now + Duration::from_millis(2),
    ) else {
        panic!("a resolved QUIC flow must forward later datagrams immediately");
    };
    assert_eq!(next.sniffed_domain.as_deref(), Some("api.example.com"));
}

#[test]
fn quic_completed_flow_lru_makes_room_for_a_fifth_sniffer() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destinations = (0..=QUIC_SNIFF_FLOW_MAX)
        .map(|index| {
            SocketAddr::new(
                "198.51.100.20".parse().unwrap(),
                443 + u16::try_from(index).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(
        (0..=QUIC_SNIFF_FLOW_MAX)
            .map(|index| {
                vec![QuicSniffOutcome::Matched(format!(
                    "node-{index}.example.com"
                ))]
            })
            .collect(),
    );

    for (index, destination) in destinations[..QUIC_SNIFF_FLOW_MAX].iter().enumerate() {
        let result = state.ingest_datagram(
            UdpDatagram::new(
                source,
                *destination,
                quic_connection_marker(&[u8::try_from(index + 1).unwrap()]),
            ),
            now + Duration::from_millis(u64::try_from(index).unwrap()),
        );
        assert!(matches!(result, QuicIngressResult::Forward(_)));
    }
    assert_eq!(state.flows.len(), QUIC_SNIFF_FLOW_MAX);

    let touched = state.ingest_datagram(
        test_udp_datagram(source, destinations[0], b"short-header"),
        now + Duration::from_millis(10),
    );
    assert!(matches!(touched, QuicIngressResult::Forward(_)));

    let QuicIngressResult::Forward(fifth) = state.ingest_datagram(
        UdpDatagram::new(
            source,
            destinations[QUIC_SNIFF_FLOW_MAX],
            quic_connection_marker(b"fifth"),
        ),
        now + Duration::from_millis(11),
    ) else {
        panic!("a completed flow must be evicted so the fifth flow can be sniffed");
    };
    assert_eq!(fifth.sniffed_domain.as_deref(), Some("node-4.example.com"));
    assert_eq!(state.flows.len(), QUIC_SNIFF_FLOW_MAX);
    assert!(state.flows.contains_key(&destinations[0]));
    assert!(!state.flows.contains_key(&destinations[1]));
    assert!(state.flows.contains_key(&destinations[2]));
    assert!(state.flows.contains_key(&destinations[3]));
    assert!(state.flows.contains_key(&destinations[4]));
}

#[test]
fn quic_pending_unverified_prefix_adopts_its_first_authenticated_initial_identity() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let initial = quic_connection_marker(b"authenticated");
    let now = TokioInstant::now();
    let mut state = scripted_quic_state_with_authentication(vec![vec![
        (QuicSniffOutcome::NeedMoreData, false),
        (
            QuicSniffOutcome::Matched("real.example.com".to_owned()),
            true,
        ),
    ]]);
    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_non_initial_marker(1, b"prefix")),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        UdpDatagram::new(source, destination, initial.clone()),
        now + Duration::from_millis(1),
    ) else {
        panic!("the first authenticated Initial must release the pending flight");
    };
    assert_eq!(replay.len(), 2);
    assert_eq!(
        replay[0].flow_id.as_ref(),
        quic_connection_key(&initial).as_ref()
    );
    assert!(replay[1].flow_id.is_none());
    assert!(
        replay
            .iter()
            .all(|prepared| { prepared.sniffed_domain.as_deref() == Some("real.example.com") })
    );
}

#[test]
fn quic_unauthenticated_first_initial_cannot_suppress_a_later_authenticated_flow() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let marker = quic_connection_marker(b"shared-dcid");
    let now = TokioInstant::now();
    let mut state = scripted_quic_state_with_authentication(vec![
        vec![(QuicSniffOutcome::NotMatched, false)],
        vec![(
            QuicSniffOutcome::Matched("real.example.com".to_owned()),
            true,
        )],
    ]);
    let QuicIngressResult::Forward(unverified) =
        state.ingest_datagram(UdpDatagram::new(source, destination, marker.clone()), now)
    else {
        panic!("an unauthenticated Initial must fail open without creating a flow identity");
    };
    assert!(unverified.flow_id.is_none());
    let QuicIngressResult::Forward(authenticated) = state.ingest_datagram(
        UdpDatagram::new(source, destination, marker.clone()),
        now + Duration::from_millis(1),
    ) else {
        panic!("a genuine Initial must retry sniffing even with the same observed DCID");
    };
    assert_eq!(
        authenticated.sniffed_domain.as_deref(),
        Some("real.example.com")
    );
    assert_eq!(
        authenticated.flow_id.as_ref(),
        quic_connection_key(&marker).as_ref()
    );
}

#[test]
fn quic_flow_identity_is_exact_and_survives_sniff_table_eviction() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let original_destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![QuicSniffOutcome::Matched(
            "stable.example.com".to_owned()
        )];
        QUIC_SNIFF_FLOW_MAX + 2
    ]);
    let marker = quic_connection_marker(b"stable");
    let expected = quic_connection_key(&marker).unwrap().routing_identity();
    let QuicIngressResult::Forward(first) = state.ingest_datagram(
        UdpDatagram::new(source, original_destination, marker.clone()),
        now,
    ) else {
        panic!("the first authenticated Initial must identify its flow");
    };
    assert_eq!(first.flow_id.unwrap().routing_identity(), expected);
    for index in 1..=QUIC_SNIFF_FLOW_MAX {
        let destination = SocketAddr::new(
            original_destination.ip(),
            443 + u16::try_from(index).unwrap(),
        );
        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(source, destination, quic_connection_marker(&[index as u8])),
                now + Duration::from_millis(u64::try_from(index).unwrap()),
            ),
            QuicIngressResult::Forward(_)
        ));
    }
    assert!(!state.flows.contains_key(&original_destination));
    let QuicIngressResult::Forward(revisited) = state.ingest_datagram(
        UdpDatagram::new(source, original_destination, marker),
        now + Duration::from_millis(10),
    ) else {
        panic!("a revisited Initial must retain its exact identity after sniff eviction");
    };
    assert_eq!(revisited.flow_id.unwrap().routing_identity(), expected);
    let zero_extended = quic_connection_key(&quic_connection_marker(b"stable\0"))
        .unwrap()
        .routing_identity();
    assert_ne!(expected, zero_extended, "the DCID length must be preserved");
    let mut v2_marker = quic_connection_marker(b"stable").to_vec();
    v2_marker[0] = 0xd0;
    v2_marker[1..5].copy_from_slice(&0x6b33_43cf_u32.to_be_bytes());
    assert_ne!(
        expected,
        quic_connection_key(&v2_marker).unwrap().routing_identity(),
        "wire version must be part of the exact flow identity"
    );
}

#[test]
fn quic_pending_flow_marks_only_first_replayed_packet_on_match_failure_and_timeout() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let now = TokioInstant::now();
    for outcome in [
        QuicSniffOutcome::Matched("matched.example.com".to_owned()),
        QuicSniffOutcome::NotMatched,
    ] {
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let marker = quic_connection_marker(b"replay");
        let mut state = scripted_quic_state(vec![vec![QuicSniffOutcome::NeedMoreData, outcome]]);
        assert!(matches!(
            state.ingest_datagram(UdpDatagram::new(source, destination, marker.clone()), now),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Replay(replay) = state.ingest_datagram(
            UdpDatagram::new(source, destination, marker.clone()),
            now + Duration::from_millis(1),
        ) else {
            panic!("a completed sniff flight must be released in order");
        };
        assert_eq!(replay.len(), 2);
        assert_eq!(
            replay[0].flow_id.as_ref(),
            quic_connection_key(&marker).as_ref()
        );
        assert!(replay[1].flow_id.is_none());
    }
    let destination: SocketAddr = "198.51.100.21:443".parse().unwrap();
    let marker = quic_connection_marker(b"timeout");
    let mut state = scripted_quic_state(vec![vec![QuicSniffOutcome::NeedMoreData]]);
    assert!(matches!(
        state.ingest_datagram(UdpDatagram::new(source, destination, marker.clone()), now),
        QuicIngressResult::Buffered
    ));
    let replay = state.expire(now + QUIC_SNIFF_TIMEOUT);
    assert_eq!(replay.len(), 1);
    assert_eq!(
        replay[0].flow_id.as_ref(),
        quic_connection_key(&marker).as_ref()
    );
    assert!(replay[0].sniffed_domain.is_none());
    assert!(state.expire(now + QUIC_SNIFF_TIMEOUT).is_empty());
}

#[tokio::test]
async fn quic_prepared_datagrams_forward_flow_identity_only_on_the_marked_send() {
    #[derive(Default)]
    struct RecordingFlowTransport {
        sent: Vec<(Datagram, Option<Vec<u8>>)>,
    }

    #[async_trait]
    impl DatagramTransport for RecordingFlowTransport {
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            self.sent.push((datagram, None));
            Ok(())
        }

        async fn send_with_flow_id(
            &mut self,
            datagram: Datagram,
            flow_id: &[u8],
        ) -> Result<(), DispatchError> {
            self.sent.push((datagram, Some(flow_id.to_vec())));
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }

    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let (responses, _responses_rx) = mpsc::channel(1);
    let context = UdpAssociationTaskContext {
        udp_timeout: Duration::from_secs(30),
        association_id: 1,
        source,
        responses,
        dispatcher: Arc::new(MockDispatcher::default()),
        resource_stats: RuntimeResourceStats::new("tun_quic_flow_identity_test"),
        association_clock: AssociationClock::realtime(),
        last_activity: Arc::new(AtomicU64::new(0)),
        tun_mtu: TUN_MTU,
        sniffer: None,
        cancellation: CancellationToken::new(),
    };
    let mut transport = RecordingFlowTransport::default();
    let marker = quic_connection_marker(b"flow");
    let identity = quic_connection_key(&marker).unwrap();
    let expected = identity.routing_identity();
    assert!(
        send_tun_udp_datagram(
            &mut transport,
            PreparedTunUdpDatagram::with_domain(
                UdpDatagram::new(source, destination, marker.clone()),
                Arc::from("sniffed.example.com"),
            )
            .with_flow_id(Some(identity)),
            &context,
        )
        .await
        .unwrap()
    );
    assert!(
        send_tun_udp_datagram(
            &mut transport,
            PreparedTunUdpDatagram::without_domain(test_udp_datagram(
                source,
                destination,
                b"unmarked",
            )),
            &context,
        )
        .await
        .unwrap()
    );
    assert_eq!(transport.sent.len(), 2);
    assert_eq!(transport.sent[0].0.remote, Destination::Ip(destination));
    assert_eq!(transport.sent[0].0.payload, marker);
    assert_eq!(
        transport.sent[0].0.sniffed_domain.as_deref(),
        Some("sniffed.example.com")
    );
    assert_eq!(transport.sent[0].1.as_deref(), Some(expected.as_slice()));
    assert_eq!(transport.sent[1].0.payload.as_ref(), b"unmarked");
    assert!(transport.sent[1].1.is_none());
}

#[test]
fn quic_completed_hint_expires_independently_while_other_destinations_stay_active() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let expired_destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let active_destination: SocketAddr = "198.51.100.21:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![QuicSniffOutcome::Matched("old.example.com".to_owned())],
        vec![QuicSniffOutcome::Matched("active.example.com".to_owned())],
        vec![QuicSniffOutcome::NotMatched],
    ]);
    for (destination, identity) in [
        (expired_destination, b"old".as_slice()),
        (active_destination, b"active".as_slice()),
    ] {
        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(source, destination, quic_connection_marker(identity)),
                now,
            ),
            QuicIngressResult::Forward(_)
        ));
    }
    assert!(matches!(
        state.ingest_datagram(
            test_udp_datagram(source, active_destination, b"keep-active"),
            now + Duration::from_secs(20),
        ),
        QuicIngressResult::Forward(_)
    ));
    let QuicIngressResult::Forward(expired) = state.ingest_datagram(
        test_udp_datagram(source, expired_destination, b"short-header"),
        now + Duration::from_secs(30),
    ) else {
        panic!("an idle completed hint must fail open without reusing its old SNI");
    };
    assert!(expired.sniffed_domain.is_none());
    let QuicIngressResult::Forward(active) = state.ingest_datagram(
        test_udp_datagram(source, active_destination, b"short-header"),
        now + Duration::from_secs(30),
    ) else {
        panic!("another destination's activity must preserve only its own hint");
    };
    assert_eq!(active.sniffed_domain.as_deref(), Some("active.example.com"));
}

#[test]
fn quic_new_dcid_replaces_a_matched_domain_for_the_same_destination() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![QuicSniffOutcome::Matched("old.example.com".to_owned())],
        vec![QuicSniffOutcome::Matched("new.example.com".to_owned())],
    ]);

    let QuicIngressResult::Forward(old) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"old")),
        now,
    ) else {
        panic!("the first QUIC connection must be sniffed");
    };
    assert_eq!(old.sniffed_domain.as_deref(), Some("old.example.com"));
    assert_eq!(
        old.flow_id.as_ref(),
        quic_connection_key(&quic_connection_marker(b"old")).as_ref()
    );

    let QuicIngressResult::Forward(new) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"new")),
        now + Duration::from_millis(1),
    ) else {
        panic!("a new DCID must create a fresh QUIC sniffer");
    };
    assert_eq!(new.sniffed_domain.as_deref(), Some("new.example.com"));
    assert_eq!(
        new.flow_id.as_ref(),
        quic_connection_key(&quic_connection_marker(b"new")).as_ref()
    );

    let QuicIngressResult::Forward(short_header) = state.ingest_datagram(
        test_udp_datagram(source, destination, b"short-header"),
        now + Duration::from_millis(2),
    ) else {
        panic!("the replacement domain must be retained for short-header traffic");
    };
    assert_eq!(
        short_header.sniffed_domain.as_deref(),
        Some("new.example.com")
    );
    assert!(short_header.flow_id.is_none());
}

#[test]
fn quic_unauthenticated_new_dcid_keeps_the_completed_domain_without_waiting() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state_with_authentication(vec![
        vec![(
            QuicSniffOutcome::Matched("stable.example.com".to_owned()),
            true,
        )],
        vec![(QuicSniffOutcome::NeedMoreData, false)],
    ]);

    let QuicIngressResult::Forward(first) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"old")),
        now,
    ) else {
        panic!("the first QUIC connection must be sniffed");
    };
    assert_eq!(first.sniffed_domain.as_deref(), Some("stable.example.com"));
    assert!(first.flow_id.is_some());

    let QuicIngressResult::Forward(candidate) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"new")),
        now + Duration::from_millis(1),
    ) else {
        panic!("an unauthenticated candidate must not enter the pending state");
    };
    assert_eq!(
        candidate.sniffed_domain.as_deref(),
        Some("stable.example.com")
    );
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
    assert!(candidate.flow_id.is_none());

    let QuicIngressResult::Forward(short_header) = state.ingest_datagram(
        test_udp_datagram(source, destination, b"short-header"),
        now + Duration::from_millis(2),
    ) else {
        panic!("the authenticated completed hint must be retained");
    };
    assert_eq!(
        short_header.sniffed_domain.as_deref(),
        Some("stable.example.com")
    );
}

#[test]
fn quic_pending_flow_accepts_a_new_header_dcid_authenticated_by_its_old_keys() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state_with_authentication(vec![vec![
        (QuicSniffOutcome::NeedMoreData, true),
        (
            QuicSniffOutcome::Matched("same-connection.example.com".to_owned()),
            true,
        ),
    ]]);

    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-a")),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-b")),
        now + Duration::from_millis(1),
    ) else {
        panic!("old Initial keys must be tried before treating a new DCID as a new flow");
    };
    assert_eq!(replay.len(), 2);
    assert_eq!(
        replay[0].flow_id.as_ref(),
        quic_connection_key(&quic_connection_marker(b"dcid-a")).as_ref()
    );
    assert!(replay[1].flow_id.is_none());
    assert!(replay.iter().all(|prepared| {
        prepared.sniffed_domain.as_deref() == Some("same-connection.example.com")
    }));
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
}

#[test]
fn quic_pending_flow_keeps_old_state_when_neither_key_authenticates_a_candidate() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state_with_authentication(vec![
        vec![
            (QuicSniffOutcome::NeedMoreData, true),
            (QuicSniffOutcome::NotMatched, false),
            (
                QuicSniffOutcome::Matched("old-flow.example.com".to_owned()),
                true,
            ),
        ],
        vec![(QuicSniffOutcome::NeedMoreData, false)],
    ]);

    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-a")),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Forward(unverified) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-b")),
        now + Duration::from_millis(1),
    ) else {
        panic!("an unverified candidate must fail open independently");
    };
    assert!(unverified.sniffed_domain.is_none());
    assert!(unverified.flow_id.is_none());
    assert_eq!(state.pending_datagrams, 1);

    let QuicIngressResult::Replay(old_flow) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"dcid-a")),
        now + Duration::from_millis(2),
    ) else {
        panic!("the old pending parser and buffered flight must be retained");
    };
    assert_eq!(old_flow.len(), 2);
    assert!(
        old_flow
            .iter()
            .all(|prepared| prepared.sniffed_domain.as_deref() == Some("old-flow.example.com"))
    );
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
}

#[test]
fn quic_zero_rtt_and_handshake_dcid_changes_do_not_reset_a_completed_hint() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![vec![QuicSniffOutcome::Matched(
        "stable.example.com".to_owned(),
    )]]);

    let QuicIngressResult::Forward(initial) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"initial")),
        now,
    ) else {
        panic!("the Initial must establish a completed hint");
    };
    assert_eq!(
        initial.sniffed_domain.as_deref(),
        Some("stable.example.com")
    );

    for (index, datagram) in [
        quic_non_initial_marker(1, b"zero-rtt"),
        quic_non_initial_marker(2, b"handshake"),
    ]
    .into_iter()
    .enumerate()
    {
        let QuicIngressResult::Forward(forwarded) = state.ingest_datagram(
            UdpDatagram::new(source, destination, datagram),
            now + Duration::from_millis(u64::try_from(index + 1).unwrap()),
        ) else {
            panic!("a non-Initial long header must not trigger a new sniffer");
        };
        assert_eq!(
            forwarded.sniffed_domain.as_deref(),
            Some("stable.example.com")
        );
        assert!(forwarded.flow_id.is_none());
    }
}

#[test]
fn unsupported_quic_version_clears_completed_hint_and_releases_pending_flight() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let completed_destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let pending_destination: SocketAddr = "198.51.100.21:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![QuicSniffOutcome::Matched(
            "must-not-leak.example.com".to_owned(),
        )],
        vec![QuicSniffOutcome::NeedMoreData],
    ]);

    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(
                source,
                completed_destination,
                quic_connection_marker(b"completed"),
            ),
            now,
        ),
        QuicIngressResult::Forward(_)
    ));
    let QuicIngressResult::Forward(unsupported) = state.ingest_datagram(
        UdpDatagram::new(
            source,
            completed_destination,
            unsupported_quic_version_marker(b"unknown"),
        ),
        now + Duration::from_millis(1),
    ) else {
        panic!("an unsupported version must fail open without waiting");
    };
    assert!(unsupported.sniffed_domain.is_none());
    assert!(unsupported.flow_id.is_none());
    let QuicIngressResult::Forward(short_header) = state.ingest_datagram(
        test_udp_datagram(source, completed_destination, b"short-header"),
        now + Duration::from_millis(2),
    ) else {
        panic!("the stale completed hint must remain cleared");
    };
    assert!(short_header.sniffed_domain.is_none());

    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(
                source,
                pending_destination,
                quic_connection_marker(b"pending"),
            ),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        UdpDatagram::new(
            source,
            pending_destination,
            unsupported_quic_version_marker(b"unknown"),
        ),
        now + Duration::from_millis(1),
    ) else {
        panic!("an unsupported version must release a pending flight");
    };
    assert_eq!(replay.len(), 2);
    assert!(
        replay
            .iter()
            .all(|prepared| prepared.sniffed_domain.is_none())
    );
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
}

#[test]
fn quic_new_dcid_retries_sniffing_after_a_no_domain_result() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![QuicSniffOutcome::NotMatched],
        vec![QuicSniffOutcome::Matched(
            "recovered.example.com".to_owned(),
        )],
    ]);

    let QuicIngressResult::Forward(first) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"old")),
        now,
    ) else {
        panic!("the first QUIC connection must fail open");
    };
    assert!(first.sniffed_domain.is_none());

    let QuicIngressResult::Forward(recovered) = state.ingest_datagram(
        UdpDatagram::new(source, destination, quic_connection_marker(b"new")),
        now + Duration::from_millis(1),
    ) else {
        panic!("a new DCID must retry sniffing after a terminal result");
    };
    assert_eq!(
        recovered.sniffed_domain.as_deref(),
        Some("recovered.example.com")
    );
}

#[test]
fn quic_new_dcid_releases_an_old_pending_flight_before_the_new_connection() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let old_payload = quic_connection_marker(b"old");
    let new_payload = quic_connection_marker(b"new");
    let mut state = scripted_quic_state_with_authentication(vec![
        vec![
            (QuicSniffOutcome::NeedMoreData, true),
            (QuicSniffOutcome::NotMatched, false),
        ],
        vec![(
            QuicSniffOutcome::Matched("new.example.com".to_owned()),
            true,
        )],
    ]);

    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(source, destination, old_payload.clone()),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        UdpDatagram::new(source, destination, new_payload.clone()),
        now + Duration::from_millis(1),
    ) else {
        panic!("a new DCID must release the stale flight before forwarding itself");
    };
    assert_eq!(replay.len(), 2);
    assert_eq!(replay[0].datagram.payload, old_payload);
    assert!(replay[0].sniffed_domain.is_none());
    assert_eq!(
        replay[0].flow_id.as_ref(),
        quic_connection_key(&old_payload).as_ref()
    );
    assert_eq!(replay[1].datagram.payload, new_payload);
    assert_eq!(replay[1].sniffed_domain.as_deref(), Some("new.example.com"));
    assert_eq!(
        replay[1].flow_id.as_ref(),
        quic_connection_key(&new_payload).as_ref()
    );
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
}

#[tokio::test]
async fn quic_association_holds_the_first_fragment_then_sends_the_original_flight() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let datagrams = Arc::new(Mutex::new(Vec::new()));
    let sent = Arc::new(Notify::new());
    let dispatcher = Arc::new(RecordingUdpDispatcher {
        datagrams: datagrams.clone(),
        sent: sent.clone(),
    });
    let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
    let (responses, _responses_rx) = mpsc::channel(4);
    let cancellation = CancellationToken::new();
    let child = cancellation.clone();
    let mut scripts = VecDeque::from([VecDeque::from([
        QuicSniffOutcome::NeedMoreData,
        QuicSniffOutcome::Matched("api.example.com".to_owned()),
    ])]);
    let task = tokio::spawn(async move {
        run_udp_association_inner_with_quic_factory(
            &mut inbound_rx,
            &UdpAssociationTaskContext {
                udp_timeout: Duration::from_secs(30),
                association_id: 1,
                source,
                responses,
                dispatcher,
                resource_stats: RuntimeResourceStats::new("tun_runtime_quic_test"),
                association_clock: AssociationClock::realtime(),
                last_activity: Arc::new(AtomicU64::new(0)),
                tun_mtu: TUN_MTU,
                sniffer: Some(test_sniffer(
                    &[],
                    &[],
                    &[PortRange {
                        start: 443,
                        end: 443,
                    }],
                )),
                cancellation: child,
            },
            move || ScriptedQuicSniffer {
                outcomes: scripts
                    .pop_front()
                    .expect("scripted QUIC flow factory exhausted"),
                authentications: VecDeque::new(),
                authenticated_initial_in_last_ingest: false,
            },
        )
        .await
    });

    inbound_tx
        .send(test_udp_datagram(source, destination, b"initial-one"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(30), sent.notified())
            .await
            .is_err(),
        "the first incomplete Initial was sent before sniffing completed"
    );
    assert!(datagrams.lock().unwrap().is_empty());

    inbound_tx
        .send(test_udp_datagram(source, destination, b"initial-two"))
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while datagrams.lock().unwrap().len() != 2 {
            sent.notified().await;
        }
    })
    .await
    .expect("the completed QUIC Initial flight was not replayed");
    {
        let recorded = datagrams.lock().unwrap();
        assert_eq!(
            recorded
                .iter()
                .map(|datagram| datagram.payload.as_ref())
                .collect::<Vec<_>>(),
            vec![b"initial-one".as_slice(), b"initial-two".as_slice()]
        );
        assert!(recorded.iter().all(|datagram| {
            datagram.remote == Destination::Ip(destination)
                && datagram.sniffed_domain.as_deref() == Some("api.example.com")
        }));
    }

    cancellation.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .expect("QUIC association did not stop")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn quic_ready_response_is_processed_before_the_next_replay_send_blocks() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let send_count = Arc::new(AtomicUsize::new(0));
    let blocked_send_started = Arc::new(Notify::new());
    let dispatcher = Arc::new(ReplayFairDispatcher {
        response: Datagram {
            remote: Destination::Ip(destination),
            payload: Bytes::from_static(b"ready-response"),
            sniffed_domain: None,
        },
        send_count: send_count.clone(),
        blocked_send_started: blocked_send_started.clone(),
    });
    let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
    let (responses, mut responses_rx) = mpsc::channel(4);
    let cancellation = CancellationToken::new();
    let child = cancellation.clone();
    let mut scripts = VecDeque::from([VecDeque::from([
        QuicSniffOutcome::NeedMoreData,
        QuicSniffOutcome::Matched("api.example.com".to_owned()),
    ])]);
    let task = tokio::spawn(async move {
        run_udp_association_inner_with_quic_factory(
            &mut inbound_rx,
            &UdpAssociationTaskContext {
                udp_timeout: Duration::from_secs(30),
                association_id: 1,
                source,
                responses,
                dispatcher,
                resource_stats: RuntimeResourceStats::new("tun_runtime_quic_fairness_test"),
                association_clock: AssociationClock::realtime(),
                last_activity: Arc::new(AtomicU64::new(0)),
                tun_mtu: TUN_MTU,
                sniffer: Some(test_sniffer(
                    &[],
                    &[],
                    &[PortRange {
                        start: 443,
                        end: 443,
                    }],
                )),
                cancellation: child,
            },
            move || ScriptedQuicSniffer {
                outcomes: scripts
                    .pop_front()
                    .expect("scripted QUIC flow factory exhausted"),
                authentications: VecDeque::new(),
                authenticated_initial_in_last_ingest: false,
            },
        )
        .await
    });

    let marker = quic_connection_marker(b"flow");
    inbound_tx
        .send(UdpDatagram::new(source, destination, marker.clone()))
        .await
        .unwrap();
    inbound_tx
        .send(UdpDatagram::new(source, destination, marker))
        .await
        .unwrap();

    let response = timeout(Duration::from_secs(1), responses_rx.recv())
        .await
        .expect("a blocked second replay send starved the ready response")
        .expect("response channel closed");
    assert_eq!(&response.payload[..], b"ready-response");
    timeout(Duration::from_secs(1), blocked_send_started.notified())
        .await
        .expect("the second replay send did not enter its blocked state");
    assert_eq!(send_count.load(Ordering::Relaxed), 2);

    cancellation.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .expect("QUIC association did not stop")
        .unwrap()
        .unwrap();
}

#[test]
fn quic_failure_and_timeout_fail_open_with_exact_buffered_payloads() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let failed_destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let timed_out_destination: SocketAddr = "198.51.100.21:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![QuicSniffOutcome::NeedMoreData, QuicSniffOutcome::NotMatched],
        vec![QuicSniffOutcome::NeedMoreData],
    ]);

    assert!(matches!(
        state.ingest_datagram(
            test_udp_datagram(source, failed_destination, b"failed-one"),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Replay(failed) = state.ingest_datagram(
        test_udp_datagram(source, failed_destination, b"failed-two"),
        now + Duration::from_millis(1),
    ) else {
        panic!("a parse failure must release the original datagrams");
    };
    assert_eq!(
        failed
            .iter()
            .map(|prepared| prepared.datagram.payload.as_ref())
            .collect::<Vec<_>>(),
        vec![b"failed-one".as_slice(), b"failed-two".as_slice()]
    );
    assert!(
        failed
            .iter()
            .all(|prepared| prepared.sniffed_domain.is_none())
    );

    assert!(matches!(
        state.ingest_datagram(
            test_udp_datagram(source, timed_out_destination, b"timed-out"),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    assert!(
        state
            .expire(now + QUIC_SNIFF_TIMEOUT - Duration::from_millis(1))
            .is_empty()
    );
    let timed_out = state.expire(now + QUIC_SNIFF_TIMEOUT);
    assert_eq!(timed_out.len(), 1);
    assert_eq!(&timed_out[0].datagram.payload[..], b"timed-out");
    assert!(timed_out[0].sniffed_domain.is_none());
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
}

#[test]
fn quic_ech_and_parser_limit_release_buffered_datagrams_without_a_domain() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let now = TokioInstant::now();
    for (index, terminal) in [
        QuicSniffOutcome::EchExtensionPresent,
        QuicSniffOutcome::LimitReached,
    ]
    .into_iter()
    .enumerate()
    {
        let destination = SocketAddr::new(
            "198.51.100.20".parse().unwrap(),
            443 + u16::try_from(index).unwrap(),
        );
        let mut state = scripted_quic_state(vec![vec![QuicSniffOutcome::NeedMoreData, terminal]]);
        assert!(matches!(
            state.ingest_datagram(test_udp_datagram(source, destination, b"initial-one"), now,),
            QuicIngressResult::Buffered
        ));
        let QuicIngressResult::Replay(replay) =
            state.ingest_datagram(test_udp_datagram(source, destination, b"initial-two"), now)
        else {
            panic!("a terminal QUIC outcome must release buffered datagrams");
        };
        assert_eq!(replay.len(), 2);
        assert!(
            replay
                .iter()
                .all(|prepared| prepared.sniffed_domain.is_none())
        );
    }
}

#[test]
fn quic_pending_datagram_and_flow_tables_are_hard_bounded() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![vec![
        QuicSniffOutcome::NeedMoreData;
        QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1
    ]]);
    for index in 0..QUIC_SNIFF_PENDING_DATAGRAM_MAX {
        assert!(matches!(
            state.ingest_datagram(
                UdpDatagram::new(source, destination, vec![u8::try_from(index).unwrap()]),
                now,
            ),
            QuicIngressResult::Buffered
        ));
    }
    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        UdpDatagram::new(source, destination, Bytes::from_static(b"overflow")),
        now,
    ) else {
        panic!("the ninth pending datagram must fail open");
    };
    assert_eq!(replay.len(), QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1);
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);

    let scripts = (0..QUIC_SNIFF_FLOW_MAX)
        .map(|_| vec![QuicSniffOutcome::NeedMoreData])
        .collect();
    let mut state = scripted_quic_state(scripts);
    for index in 0..QUIC_SNIFF_FLOW_MAX {
        let destination = SocketAddr::new(
            "198.51.100.20".parse().unwrap(),
            443 + u16::try_from(index).unwrap(),
        );
        assert!(matches!(
            state.ingest_datagram(test_udp_datagram(source, destination, b"pending"), now,),
            QuicIngressResult::Buffered
        ));
    }
    let overflow_destination: SocketAddr = "198.51.100.30:8443".parse().unwrap();
    let QuicIngressResult::Forward(overflow) = state.ingest_datagram(
        test_udp_datagram(source, overflow_destination, b"fifth-flow"),
        now,
    ) else {
        panic!("a fifth QUIC flow must fail open without creating a parser");
    };
    assert!(overflow.sniffed_domain.is_none());
    assert_eq!(state.flows.len(), QUIC_SNIFF_FLOW_MAX);
}

#[test]
fn quic_pending_byte_budget_accepts_32_kib_and_replays_the_overflow_datagram() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![vec![
        QuicSniffOutcome::NeedMoreData,
        QuicSniffOutcome::NeedMoreData,
    ]]);

    assert!(matches!(
        state.ingest_datagram(
            UdpDatagram::new(
                source,
                destination,
                vec![0xaa; QUIC_SNIFF_PENDING_BYTES_MAX],
            ),
            now,
        ),
        QuicIngressResult::Buffered
    ));
    assert_eq!(state.pending_datagrams, 1);
    assert_eq!(state.pending_bytes, QUIC_SNIFF_PENDING_BYTES_MAX);

    let QuicIngressResult::Replay(replay) = state.ingest_datagram(
        UdpDatagram::new(source, destination, Bytes::from_static(b"x")),
        now,
    ) else {
        panic!("a datagram above the aggregate byte budget must fail open");
    };
    assert_eq!(replay.len(), 2);
    assert_eq!(
        replay[0].datagram.payload.len(),
        QUIC_SNIFF_PENDING_BYTES_MAX
    );
    assert_eq!(&replay[1].datagram.payload[..], b"x");
    assert_eq!(state.pending_datagrams, 0);
    assert_eq!(state.pending_bytes, 0);
}

#[test]
fn quic_flow_state_is_isolated_by_destination_and_unconfigured_ports_are_skipped() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination_a: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let destination_b: SocketAddr = "198.51.100.21:443".parse().unwrap();
    let now = TokioInstant::now();
    let mut state = scripted_quic_state(vec![
        vec![
            QuicSniffOutcome::NeedMoreData,
            QuicSniffOutcome::Matched("a.example.com".to_owned()),
        ],
        vec![QuicSniffOutcome::Matched("b.example.com".to_owned())],
    ]);

    assert!(matches!(
        state.ingest_datagram(test_udp_datagram(source, destination_a, b"a-one"), now,),
        QuicIngressResult::Buffered
    ));
    let QuicIngressResult::Forward(b) =
        state.ingest_datagram(test_udp_datagram(source, destination_b, b"b-one"), now)
    else {
        panic!("one destination must not wait for another destination");
    };
    assert_eq!(b.sniffed_domain.as_deref(), Some("b.example.com"));
    let QuicIngressResult::Replay(a) =
        state.ingest_datagram(test_udp_datagram(source, destination_a, b"a-two"), now)
    else {
        panic!("the first destination must retain its independent parser");
    };
    assert!(
        a.iter()
            .all(|prepared| prepared.sniffed_domain.as_deref() == Some("a.example.com"))
    );

    let config = test_sniffer(
        &[],
        &[],
        &[PortRange {
            start: 443,
            end: 443,
        }],
    );
    assert!(configured_quic_sniffing(Some(&config), 443));
    assert!(!configured_quic_sniffing(Some(&config), 8_443));
    assert!(!configured_quic_sniffing(None, 443));
}

#[test]
fn tun_response_capacities_are_independent_of_tcp_accept_and_each_other() {
    let tun = ResourceLimits::default();
    assert_eq!(tun.tun_udp_response_queue_capacity, 256);
    assert_eq!(tun.tun_dns_response_queue_capacity, 128);
    let altered = ResourceLimits {
        event_queue_capacity: 3,
        tun_udp_association_queue_capacity: 2,
        tun_udp_response_queue_capacity: 5,
        tun_dns_response_queue_capacity: 7,
        ..tun
    };
    let config = tun_netstack_config(altered, false);
    assert_eq!(config.tcp_accept_queue, 3);
    assert_eq!(altered.tun_udp_association_queue_capacity, 2);
    assert_eq!(altered.tun_udp_response_queue_capacity, 5);
    assert_eq!(altered.tun_dns_response_queue_capacity, 7);
}

#[tokio::test]
async fn ready_udp_receive_bursts_let_the_response_writer_run_without_drops() {
    assert_ready_udp_receive_bursts(1, UdpBurstConsumer::Ready).await;
}

#[tokio::test]
async fn concurrent_ready_udp_sources_let_the_response_writer_run_without_drops() {
    assert_ready_udp_receive_bursts(8, UdpBurstConsumer::Ready).await;
}

#[tokio::test]
async fn backpressured_udp_response_handoff_retains_one_packet_and_duplex_progress() {
    assert_ready_udp_receive_bursts(8, UdpBurstConsumer::Delayed).await;
}

#[tokio::test]
async fn backpressured_udp_response_handoff_stops_without_waiting_for_the_writer() {
    assert_ready_udp_receive_bursts(8, UdpBurstConsumer::Stopped).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpBurstConsumer {
    Ready,
    Delayed,
    Stopped,
}

async fn assert_ready_udp_receive_bursts(sources: usize, consumer: UdpBurstConsumer) {
    const PACKETS: u32 = 512;
    struct BurstDispatcher(SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>);
    struct BurstDatagrams {
        remote: SocketAddr,
        sequence: u32,
        received: Arc<AtomicUsize>,
        sent: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Dispatcher for BurstDispatcher {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::Other("unused memory TCP path".into()))
        }
        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Ok(Box::new(BurstDatagrams {
                remote: self.0,
                sequence: 0,
                received: self.1.clone(),
                sent: self.2.clone(),
            }))
        }
    }
    #[async_trait]
    impl DatagramTransport for BurstDatagrams {
        async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
            self.sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if self.sequence == PACKETS {
                std::future::pending::<()>().await;
            }
            // A real Tokio UDP readiness operation also charges cooperation.
            // The native quantum alone can exceed this writer handoff queue.
            tokio::task::consume_budget().await;
            let payload = Bytes::copy_from_slice(&self.sequence.to_be_bytes());
            self.sequence += 1;
            self.received.fetch_add(1, Ordering::Relaxed);
            Ok(Datagram {
                remote: Destination::Ip(self.remote),
                payload,
                sniffed_domain: None,
            })
        }
    }
    let remote = "198.51.100.20:443".parse().unwrap();
    let (responses, mut output) = mpsc::channel(64);
    let cancellation = CancellationToken::new();
    let stats = RuntimeResourceStats::new("udp_receive_burst_test");
    let mut inbound = Vec::new();
    let mut producers = Vec::new();
    let read_count = Arc::new(AtomicUsize::new(0));
    let send_count = Arc::new(AtomicUsize::new(0));
    for index in 0..sources {
        let source = SocketAddr::new("192.0.2.10".parse().unwrap(), 12000 + index as u16);
        let (sender, mut input) = mpsc::channel(1);
        inbound.push(sender);
        let context = UdpAssociationTaskContext {
            association_id: index as u64 + 1,
            source,
            responses: responses.clone(),
            dispatcher: Arc::new(BurstDispatcher(
                remote,
                read_count.clone(),
                send_count.clone(),
            )),
            resource_stats: stats.clone(),
            association_clock: AssociationClock::realtime(),
            last_activity: Arc::new(AtomicU64::new(0)),
            tun_mtu: TUN_MTU,
            udp_timeout: Duration::from_secs(30),
            sniffer: None,
            cancellation: cancellation.clone(),
        };
        producers.push(tokio::spawn(async move {
            run_udp_association_inner(&mut input, &context).await
        }));
    }
    if consumer != UdpBurstConsumer::Ready {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(output.len(), output.max_capacity());
        assert!(
            read_count.load(Ordering::Relaxed) <= output.max_capacity() + sources,
            "a blocked writer must retain at most one extra response per source"
        );
        for (index, sender) in inbound.iter().enumerate() {
            let source = SocketAddr::new("192.0.2.10".parse().unwrap(), 12000 + index as u16);
            sender
                .try_send(UdpDatagram::new(source, remote, b"uplink".as_slice()))
                .unwrap();
        }
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(send_count.load(Ordering::Relaxed), sources);
    }
    let received = if consumer == UdpBurstConsumer::Stopped {
        Ok(true)
    } else {
        timeout(Duration::from_millis(200), async {
            let mut next = vec![0_u32; sources];
            for _ in 0..PACKETS as usize * sources {
                let response = output.recv().await.expect("memory UDP producer closed");
                let index = usize::from(response.destination.port().saturating_sub(12000));
                if response.source != remote
                    || response.destination
                        != SocketAddr::new("192.0.2.10".parse().unwrap(), 12000 + index as u16)
                    || index >= sources
                    || response.payload[..] != next[index].to_be_bytes()
                {
                    return false;
                }
                next[index] += 1;
                // The real writer charges each emitted packet in addition to
                // channel reception, even when all producers remain ready.
                tokio::task::consume_budget().await;
            }
            true
        })
        .await
    };
    cancellation.cancel();
    for producer in producers {
        timeout(Duration::from_secs(1), producer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    drop(inbound);
    assert!(
        matches!(received, Ok(true)),
        "ready receive burst starved the response writer"
    );
    assert_eq!(
        stats.snapshot().udp_response_queue_drops,
        if consumer == UdpBurstConsumer::Stopped {
            sources as u64
        } else {
            0
        }
    );
}

#[tokio::test]
async fn default_udp_response_queue_absorbs_bounded_bursts_without_blocking_dns() {
    let stats = RuntimeResourceStats::new("tun_response_capacity_test");
    let cancellation = CancellationToken::new();
    let (mut ingress, mut ordinary, mut dns) = UdpIngress::new(
        UdpIngressContext {
            resources: None,
            config: test_tun_config(),
            dispatcher: Arc::new(MockDispatcher::default()),
            dns: None,
            sniffer: None,
            limits: ResourceLimits::default(),
            resource_stats: stats.clone(),
        },
        cancellation.clone(),
    );
    assert_eq!(ordinary.max_capacity(), 256);
    assert_eq!(dns.max_capacity(), 128);
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let server: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let response =
        |sequence: u32| UdpDatagram::new(server, source, sequence.to_be_bytes().to_vec());
    let last_activity = AtomicU64::new(5);
    for sequence in 0..256 {
        assert!(matches!(
            try_queue_tun_udp_response(
                &ingress.responses,
                response(sequence),
                &last_activity,
                u64::from(sequence) + 100,
            ),
            ResponseQueueResult::Queued
        ));
    }
    assert_eq!(ordinary.len(), 256);
    let ResponseQueueResult::Pending(pending) =
        try_queue_tun_udp_response(&ingress.responses, response(256), &last_activity, 5_000)
    else {
        panic!("full queue must return its uncommitted response")
    };
    assert_eq!(last_activity.load(Ordering::Acquire), 355);
    assert_eq!(stats.snapshot().udp_response_queue_drops, 0);
    assert_eq!(stats.snapshot().udp_association_queue_drops, 0);
    assert_eq!(stats.snapshot().dns_queue_drops, 0);

    // Saturating the ordinary channel neither consumes DNS capacity nor
    // overwrites any accepted response. Freeing one slot admits the held packet.
    try_queue_tun_dns_response(&ingress.dns_responses, response(7), None, &stats);
    assert_eq!(&dns.try_recv().unwrap().payload[..], 7_u32.to_be_bytes());
    assert_eq!(
        &ordinary.try_recv().unwrap().payload[..],
        0_u32.to_be_bytes()
    );
    assert!(matches!(
        try_queue_tun_udp_response(&ingress.responses, pending, &last_activity, 5_001,),
        ResponseQueueResult::Queued
    ));
    for sequence in 1_u32..256 {
        assert_eq!(
            &ordinary.try_recv().unwrap().payload[..],
            sequence.to_be_bytes()
        );
    }
    assert_eq!(
        &ordinary.try_recv().unwrap().payload[..],
        256_u32.to_be_bytes()
    );
    assert!(matches!(
        ordinary.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    ordinary.close();
    assert!(matches!(
        try_queue_tun_udp_response(&ingress.responses, response(258), &last_activity, 6_000,),
        ResponseQueueResult::Closed
    ));
    assert_eq!(last_activity.load(Ordering::Acquire), 5_001);
    assert_eq!(stats.snapshot().udp_queue_drops, 0);
    assert_eq!(stats.snapshot().dns_queue_drops, 0);
    ingress.stop().await;
    assert!(!cancellation.is_cancelled());
}

#[test]
fn tun_netstack_keeps_queue_and_per_flow_bounds_without_a_flow_count_ceiling() {
    let limits = ResourceLimits::default();
    let config = tun_netstack_config(limits, false);

    assert_eq!(config.tcp_accept_queue, limits.event_queue_capacity);
    assert_eq!(config.tcp_recv_buffer, limits.tcp_buffer_per_direction);
    assert_eq!(config.tcp_send_buffer, limits.tcp_buffer_per_direction);
    assert_eq!(config.mtu, 1_500);
    assert_eq!(limits.max_datagram_size, 65_535);
}

fn test_association(
    generation: u64,
    last_activity: u64,
) -> (
    UdpAssociation,
    mpsc::Receiver<UdpDatagram>,
    CancellationToken,
) {
    let (sender, receiver) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    (
        UdpAssociation {
            generation,
            sender,
            cancellation: cancellation.clone(),
            last_activity: Arc::new(AtomicU64::new(last_activity)),
        },
        receiver,
        cancellation,
    )
}

#[test]
fn stale_association_completion_cannot_remove_a_replacement_generation() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let (replacement, _receiver, _) = test_association(2, 0);
    let mut associations = HashMap::from([(source, replacement)]);

    assert!(remove_completed_association(&mut associations, source, 1).is_none());
    assert_eq!(associations.get(&source).unwrap().generation, 2);
    assert!(remove_completed_association(&mut associations, source, 2).is_some());
    assert!(associations.is_empty());
}

#[test]
fn association_activity_clock_refreshes_only_successfully_queued_work() {
    let tick = Arc::new(AtomicU64::new(100));
    let clock = AssociationClock::injected(tick.clone());
    let (association, mut receiver, _) = test_association(1, 5);
    let stats = RuntimeResourceStats::new("tun_runtime_test");
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();

    assert!(matches!(
        try_queue_association_input(
            &association,
            UdpPacketView {
                source,
                destination,
                payload: b"queued"
            },
            clock.now(),
            1,
            &stats,
        ),
        AssociationInputResult::Queued
    ));
    assert_eq!(association.last_activity.load(Ordering::Acquire), 100);

    tick.store(110, Ordering::Release);
    assert!(matches!(
        try_queue_association_input(
            &association,
            UdpPacketView {
                source,
                destination,
                payload: b"full"
            },
            clock.now(),
            1,
            &stats,
        ),
        AssociationInputResult::Full
    ));
    assert_eq!(association.last_activity.load(Ordering::Acquire), 100);
    assert_eq!(stats.snapshot().udp_queue_drops, 1);
    assert_eq!(stats.snapshot().udp_association_queue_drops, 1);
    assert_eq!(stats.snapshot().udp_response_queue_drops, 0);

    receiver.try_recv().unwrap();
    drop(receiver);
    tick.store(120, Ordering::Release);
    assert!(matches!(
        try_queue_association_input(
            &association,
            UdpPacketView {
                source,
                destination,
                payload: b"closed"
            },
            clock.now(),
            1,
            &stats,
        ),
        AssociationInputResult::Closed
    ));
    assert_eq!(association.last_activity.load(Ordering::Acquire), 100);
}

#[test]
fn periodic_cleanup_removes_expired_and_closed_but_preserves_active_entries() {
    let now = 100;
    let expired_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let closed_source: SocketAddr = "192.0.2.11:12001".parse().unwrap();
    let active_source: SocketAddr = "192.0.2.12:12002".parse().unwrap();
    let (expired, _expired_receiver, expired_cancellation) = test_association(1, 70);
    let (closed, closed_receiver, closed_cancellation) = test_association(2, 99);
    let (active, _active_receiver, _) = test_association(3, 80);
    drop(closed_receiver);
    let mut associations = HashMap::from([
        (expired_source, expired),
        (closed_source, closed),
        (active_source, active),
    ]);

    let removed =
        take_expired_or_closed_associations(&mut associations, now, Duration::from_secs(30));
    assert_eq!(removed.len(), 2);
    assert!(associations.contains_key(&active_source));
    assert!(!expired_cancellation.is_cancelled());
    assert!(!closed_cancellation.is_cancelled());
    cancel_removed_associations(removed);
    assert!(expired_cancellation.is_cancelled());
    assert!(closed_cancellation.is_cancelled());
}

#[derive(Default)]
struct MockDispatcher {
    tcp_sessions: Mutex<Vec<StreamSession>>,
    udp_sessions: Mutex<Vec<DatagramSession>>,
    tcp_called: Notify,
    udp_response_ready: Arc<Notify>,
}

#[async_trait]
impl Dispatcher for MockDispatcher {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.tcp_sessions.lock().unwrap().push(session);
        self.tcp_called.notify_one();
        let (client, mut server) = tokio::io::duplex(1_024);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 256];
            while let Ok(size) = server.read(&mut buffer).await {
                if size == 0 || server.write_all(&buffer[..size]).await.is_err() {
                    break;
                }
            }
        });
        Ok(Box::new(client))
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.udp_sessions.lock().unwrap().push(session);
        let mut transport = EchoDatagrams::new();
        transport.response_ready = Some(self.udp_response_ready.clone());
        Ok(Box::new(transport))
    }
}

struct EchoDatagrams {
    sender: mpsc::Sender<Datagram>,
    receiver: mpsc::Receiver<Datagram>,
    response_ready: Option<Arc<Notify>>,
}

struct BlockingDispatcher {
    send_started: Arc<Notify>,
    send_count: Arc<AtomicUsize>,
    open_count: Arc<AtomicUsize>,
}

struct RecordingUdpDispatcher {
    datagrams: Arc<Mutex<Vec<Datagram>>>,
    sent: Arc<Notify>,
}

struct RecordingUdpTransport {
    datagrams: Arc<Mutex<Vec<Datagram>>>,
    sent: Arc<Notify>,
}

struct ReplayFairDispatcher {
    response: Datagram,
    send_count: Arc<AtomicUsize>,
    blocked_send_started: Arc<Notify>,
}

struct ReplayFairDatagrams {
    response: Option<Datagram>,
    send_count: Arc<AtomicUsize>,
    blocked_send_started: Arc<Notify>,
}

#[async_trait]
impl Dispatcher for RecordingUdpDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::Other("unused TCP path".to_owned()))
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(RecordingUdpTransport {
            datagrams: self.datagrams.clone(),
            sent: self.sent.clone(),
        }))
    }
}

#[async_trait]
impl DatagramTransport for RecordingUdpTransport {
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.datagrams.lock().unwrap().push(datagram);
        self.sent.notify_one();
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
}

#[async_trait]
impl Dispatcher for ReplayFairDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::Other("unused TCP path".to_owned()))
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(ReplayFairDatagrams {
            response: Some(self.response.clone()),
            send_count: self.send_count.clone(),
            blocked_send_started: self.blocked_send_started.clone(),
        }))
    }
}

#[async_trait]
impl DatagramTransport for ReplayFairDatagrams {
    async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
        let send_index = self.send_count.fetch_add(1, Ordering::Relaxed);
        if send_index == 0 {
            return Ok(());
        }
        self.blocked_send_started.notify_one();
        std::future::pending().await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.send_count.load(Ordering::Relaxed) != 0
            && let Some(response) = self.response.take()
        {
            return Ok(response);
        }
        std::future::pending().await
    }
}

#[async_trait]
impl Dispatcher for BlockingDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::Other("unused TCP path".to_owned()))
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.open_count.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(BlockingDatagrams {
            send_started: self.send_started.clone(),
            send_count: Some(self.send_count.clone()),
        }))
    }
}

struct BlockingDatagrams {
    send_started: Arc<Notify>,
    send_count: Option<Arc<AtomicUsize>>,
}

#[derive(Default)]
struct DnsReplyDispatcher {
    udp_sessions: Mutex<Vec<DatagramSession>>,
}

#[async_trait]
impl Dispatcher for DnsReplyDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::Other("unused TCP path".to_owned()))
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.udp_sessions.lock().unwrap().push(session);
        Ok(Box::new(DnsReplyDatagrams::new()))
    }
}

struct DnsReplyDatagrams {
    sender: mpsc::Sender<Datagram>,
    receiver: mpsc::Receiver<Datagram>,
}

impl DnsReplyDatagrams {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Self { sender, receiver }
    }
}

#[async_trait]
impl DatagramTransport for DnsReplyDatagrams {
    async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
        let query = classify_query(&datagram.payload)
            .map_err(|error| DispatchError::Other(error.to_string()))?;
        datagram.payload = synthesize_empty_response(&query, 0)
            .map_err(|error| DispatchError::Other(error.to_string()))?
            .into();
        self.sender
            .send(datagram)
            .await
            .map_err(|_| DispatchError::Other("DNS reply transport stopped".to_owned()))
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| DispatchError::Other("DNS reply transport stopped".to_owned()))
    }
}

struct ResponseFirstDispatcher {
    response: Datagram,
}

struct SourceSelectiveDispatcher {
    blocked_source: SocketAddr,
    send_started: Arc<Notify>,
}

#[async_trait]
impl Dispatcher for ResponseFirstDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::Other("unused TCP path".to_owned()))
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(ResponseFirstDatagrams {
            response: Some(self.response.clone()),
        }))
    }
}

#[async_trait]
impl Dispatcher for SourceSelectiveDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::Other("unused TCP path".to_owned()))
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if session.source == self.blocked_source {
            Ok(Box::new(BlockingDatagrams {
                send_started: self.send_started.clone(),
                send_count: None,
            }))
        } else {
            Ok(Box::new(EchoDatagrams::new()))
        }
    }
}

struct ResponseFirstDatagrams {
    response: Option<Datagram>,
}

#[async_trait]
impl DatagramTransport for ResponseFirstDatagrams {
    async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
        std::future::pending().await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if let Some(response) = self.response.take() {
            return Ok(response);
        }
        std::future::pending().await
    }
}

#[async_trait]
impl DatagramTransport for BlockingDatagrams {
    async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
        if let Some(send_count) = &self.send_count {
            send_count.fetch_add(1, Ordering::Relaxed);
        }
        self.send_started.notify_one();
        std::future::pending().await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
}

impl EchoDatagrams {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Self {
            sender,
            receiver,
            response_ready: None,
        }
    }
}

#[async_trait]
impl DatagramTransport for EchoDatagrams {
    async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
        if datagram.payload.as_ref() == b"oversize-response" {
            datagram.payload = Bytes::from(vec![0_u8; TUN_MTU]);
        }
        self.sender
            .send(datagram)
            .await
            .map_err(|_| DispatchError::Other("echo transport stopped".to_owned()))
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let datagram = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| DispatchError::Other("echo transport stopped".to_owned()))?;
        if let Some(ready) = &self.response_ready {
            ready.notify_one();
        }
        Ok(datagram)
    }
}

fn test_runtime_dns(dispatcher: Arc<dyn Dispatcher>) -> Arc<RuntimeDns> {
    let config = DnsConfig {
        enable: true,
        ipv6: true,
        nameservers: vec![DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Udp,
            address: Ipv4Addr::new(198, 51, 100, 53).into(),
            port: 53,
            route: DnsRoute::Direct,
        }],
        nameserver_policies: Vec::new(),
        ..DnsConfig::default()
    };
    let proxies = ProxyDispatchers::new(vec![dispatcher.clone()]).unwrap();
    let rules = RuleSet::compile(vec![RuleSpec {
        kind: RuleKind::Match,
        action: RuleAction::Direct,
        no_resolve: false,
    }])
    .unwrap();
    let limits = ResourceLimits::default();
    Arc::new(RuntimeDns::new_routed_proxies_with_cache_limits(
        &config,
        proxies,
        dispatcher,
        rules,
        Arc::new(EmptyGeoMatcher),
        limits.dns_address_cache_entries,
        limits.dns_redir_host_entries,
    ))
}

#[tokio::test]
async fn synthetic_fd_with_dns_disabled_dispatches_tcp_and_reuses_udp_association() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let limits = ResourceLimits {
        packet_queue_capacity: 8,
        event_queue_capacity: 4,
        tun_max_datagram_size: 1_400,
        ..ResourceLimits::default()
    };
    let runtime = TunRuntime::new(
        tun,
        limits,
        dispatcher.clone(),
        None,
        true,
        false,
        Some(test_sniffer(
            &[PortRange {
                start: 8_080,
                end: 8_080,
            }],
            &[],
            &[],
        )),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));

    let udp_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let udp_destination: SocketAddr = "198.51.100.20:53".parse().unwrap();

    let mut oversized_ingress = vec![0_u8; TUN_MTU + 1];
    oversized_ingress[0] = 0x45;
    peer.send(&oversized_ingress).await.unwrap();

    peer.send(&build_udp(
        udp_source,
        udp_destination,
        b"oversize-response",
    ))
    .await
    .unwrap();
    let mut dropped = [0_u8; TUN_MTU];
    assert!(
        timeout(Duration::from_millis(100), peer.recv(&mut dropped))
            .await
            .is_err(),
        "oversized UDP response unexpectedly reached TUN",
    );

    for destination in ["198.51.100.20:53", "203.0.113.30:443"] {
        let destination: SocketAddr = destination.parse().unwrap();
        peer.send(&build_udp(udp_source, destination, b"query"))
            .await
            .unwrap();
        let mut response = [0_u8; TUN_MTU];
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .expect("UDP response timed out")
            .unwrap();
        assert_udp_response(&response[..size], destination, udp_source, b"query");
    }
    assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert_eq!(
        dispatcher.udp_sessions.lock().unwrap()[0],
        DatagramSession::for_tun(udp_source, 1_400)
    );

    let tcp_source: SocketAddr = "192.0.2.11:13000".parse().unwrap();
    let tcp_destination: SocketAddr = "198.51.100.21:8080".parse().unwrap();
    peer.send(&build_tcp_syn(tcp_source, tcp_destination))
        .await
        .unwrap();
    let mut syn_ack = [0_u8; TUN_MTU];
    let size = timeout(Duration::from_secs(2), peer.recv(&mut syn_ack))
        .await
        .expect("TCP SYN-ACK timed out")
        .unwrap();
    assert!(size >= 40);
    assert_eq!(syn_ack[20 + 13] & 0x12, 0x12);
    let server_sequence = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
    let request = b"GET / HTTP/1.1\r\nHost: Sniff.Example.COM\r\n\r\n";
    peer.send(&build_tcp_segment(
        tcp_source,
        tcp_destination,
        2,
        server_sequence.wrapping_add(1),
        0x18,
        request,
    ))
    .await
    .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if !dispatcher.tcp_sessions.lock().unwrap().is_empty() {
                break;
            }
            dispatcher.tcp_called.notified().await;
        }
    })
    .await
    .expect("TCP dispatcher was not called");
    assert_eq!(
        dispatcher.tcp_sessions.lock().unwrap()[0],
        StreamSession {
            metadata: crate::session::InboundMetadata::new(tcp_destination.port()),
            inbound: InboundKind::Tun,
            source: tcp_source,
            destination: Destination::Ip(tcp_destination),
            sniffed_domain: Some("sniff.example.com".to_owned()),
        }
    );
    let echoed = timeout(Duration::from_secs(2), async {
        let mut echoed = Vec::with_capacity(request.len());
        while echoed.len() < request.len() {
            let size = peer.recv(&mut syn_ack).await.unwrap();
            if size < 40 || syn_ack[9] != 6 {
                continue;
            }
            let ip_header_length = usize::from(syn_ack[0] & 0x0f) * 4;
            let tcp_header_length = usize::from(syn_ack[ip_header_length + 12] >> 4) * 4;
            let payload_offset = ip_header_length + tcp_header_length;
            if payload_offset < size {
                echoed.extend_from_slice(&syn_ack[payload_offset..size]);
            }
        }
        echoed
    })
    .await
    .expect("sniffed TCP prefix was not replayed through the outbound");
    assert_eq!(echoed, request);

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("TUN runtime stop timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn unconfigured_tls_port_dispatches_without_reading_a_prefix() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let limits = ResourceLimits {
        packet_queue_capacity: 4,
        event_queue_capacity: 2,
        tun_max_datagram_size: TUN_MTU,
        ..ResourceLimits::default()
    };
    let runtime = TunRuntime::new(
        tun,
        limits,
        dispatcher.clone(),
        None,
        true,
        false,
        Some(test_sniffer(
            &[],
            &[PortRange {
                start: 8_443,
                end: 8_443,
            }],
            &[],
        )),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));

    let source: SocketAddr = "192.0.2.12:14000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.22:443".parse().unwrap();
    peer.send(&build_tcp_syn(source, destination))
        .await
        .unwrap();
    let mut syn_ack = [0_u8; TUN_MTU];
    let size = timeout(Duration::from_secs(2), peer.recv(&mut syn_ack))
        .await
        .expect("TCP SYN-ACK timed out")
        .unwrap();
    assert!(size >= 40);
    assert_eq!(syn_ack[20 + 13] & 0x12, 0x12);
    let server_sequence = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());

    // Complete the handshake without sending any TLS bytes. A mistakenly
    // enabled sniffer would wait for its 200 ms read deadline here.
    peer.send(&build_tcp_segment(
        source,
        destination,
        2,
        server_sequence.wrapping_add(1),
        0x10,
        &[],
    ))
    .await
    .unwrap();
    timeout(Duration::from_millis(100), async {
        loop {
            if !dispatcher.tcp_sessions.lock().unwrap().is_empty() {
                break;
            }
            dispatcher.tcp_called.notified().await;
        }
    })
    .await
    .expect("unconfigured TLS port delayed dispatch for a prefix read");
    assert_eq!(
        dispatcher.tcp_sessions.lock().unwrap()[0],
        StreamSession {
            metadata: crate::session::InboundMetadata::new(destination.port()),
            inbound: InboundKind::Tun,
            source,
            destination: Destination::Ip(destination),
            sniffed_domain: None,
        }
    );

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("TUN runtime stop timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn enabled_dns_fast_path_replies_without_opening_a_tun_udp_association() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let dns_dispatcher = Arc::new(DnsReplyDispatcher::default());
    let dns = test_runtime_dns(dns_dispatcher.clone());
    let limits = ResourceLimits {
        packet_queue_capacity: 16,
        event_queue_capacity: 8,
        tun_max_datagram_size: TUN_MTU,
        ..ResourceLimits::default()
    };
    let runtime = TunRuntime::new(
        tun,
        limits,
        dispatcher.clone(),
        Some(dns),
        true,
        false,
        Some(test_sniffer(&[], &[], &[PortRange { start: 53, end: 53 }])),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));

    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    peer.send(&build_udp(source, requested_server, b"invalid"))
        .await
        .unwrap();
    let mut response = [0_u8; TUN_MTU];
    assert!(
        timeout(Duration::from_millis(100), peer.recv(&mut response))
            .await
            .is_err(),
        "malformed DNS query unexpectedly produced a response",
    );
    assert!(dispatcher.udp_sessions.lock().unwrap().is_empty());
    assert!(dns_dispatcher.udp_sessions.lock().unwrap().is_empty());

    let query = build_query(0x1234, "example.com", QueryType::A).unwrap();
    peer.send(&build_udp(source, requested_server, &query))
        .await
        .unwrap();
    let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
        .await
        .expect("TUN DNS response timed out")
        .unwrap();
    assert!(size > 30);
    assert_eq!(response[9], 17);
    assert_eq!(
        u16::from_be_bytes(response[20..22].try_into().unwrap()),
        requested_server.port()
    );
    assert_eq!(
        u16::from_be_bytes(response[22..24].try_into().unwrap()),
        source.port()
    );
    assert_ne!(response[30] & 0x80, 0);
    assert_eq!(&response[28..30], &0x1234_u16.to_be_bytes());
    assert!(dispatcher.udp_sessions.lock().unwrap().is_empty());
    assert_eq!(dns_dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert_eq!(
        dns_dispatcher.udp_sessions.lock().unwrap()[0].inbound,
        InboundKind::InternalDns
    );

    let ordinary_destination: SocketAddr = "203.0.113.30:443".parse().unwrap();
    peer.send(&build_udp(source, ordinary_destination, b"ordinary"))
        .await
        .unwrap();
    let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
        .await
        .expect("ordinary UDP response timed out")
        .unwrap();
    assert_udp_response(&response[..size], ordinary_destination, source, b"ordinary");
    assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("TUN runtime stop timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn queued_dns_response_is_bounded_and_a_full_queue_drops_the_new_response() {
    let dns = test_runtime_dns(Arc::new(DnsReplyDispatcher::default()));
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let request = UdpDatagram::new(
        source,
        requested_server,
        build_query(0x2100, "queued.example", QueryType::A).unwrap(),
    );
    let (responses, mut queued) = mpsc::channel(1);
    let resource_stats = RuntimeResourceStats::new("tun_runtime_test");

    let permit = dns.begin_query();
    run_tun_dns_query(
        dns.clone(),
        permit,
        request,
        responses.clone(),
        TUN_MTU,
        resource_stats.clone(),
        CancellationToken::new(),
    )
    .await;
    let response = queued.recv().await.unwrap();
    assert_eq!(response.source, requested_server);
    assert_eq!(response.destination, source);
    drop(response);

    responses
        .send(QueuedUdpResponse::ordinary(UdpDatagram::new(
            requested_server,
            source,
            b"occupied".as_slice(),
        )))
        .await
        .unwrap();
    let request = UdpDatagram::new(
        source,
        requested_server,
        build_query(0x2101, "full.example", QueryType::A).unwrap(),
    );
    let permit = dns.begin_query();
    run_tun_dns_query(
        dns.clone(),
        permit,
        request,
        responses,
        TUN_MTU,
        resource_stats.clone(),
        CancellationToken::new(),
    )
    .await;
    assert_eq!(resource_stats.snapshot().dns_queue_drops, 1);
    assert_eq!(&queued.recv().await.unwrap().payload[..], b"occupied");
}

#[tokio::test]
async fn ordinary_and_dns_responses_have_independent_queue_capacity() {
    let dns = test_runtime_dns(Arc::new(DnsReplyDispatcher::default()));
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let stats = RuntimeResourceStats::new("tun_runtime_test");
    let (ordinary_tx, mut ordinary_rx) = mpsc::channel(1);
    let (dns_tx, mut dns_rx) = mpsc::channel(1);

    ordinary_tx
        .send(QueuedUdpResponse::ordinary(UdpDatagram::new(
            server,
            source,
            b"ordinary-occupied".as_slice(),
        )))
        .await
        .unwrap();
    let permit = dns.begin_query();
    try_queue_tun_dns_response(
        &dns_tx,
        UdpDatagram::new(server, source, b"dns-independent".as_slice()),
        Some(permit),
        &stats,
    );

    let dns_response = dns_rx.recv().await.unwrap();
    assert_eq!(&dns_response.payload[..], b"dns-independent");
    drop(dns_response);
    assert_eq!(
        &ordinary_rx.recv().await.unwrap().payload[..],
        b"ordinary-occupied"
    );
}

#[tokio::test]
async fn full_ordinary_response_queue_returns_data_without_refreshing_activity() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let server: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let last_activity = AtomicU64::new(5);
    let (responses, mut queued) = mpsc::channel(1);

    assert!(matches!(
        try_queue_tun_udp_response(
            &responses,
            UdpDatagram::new(server, source, b"queued".as_slice()),
            &last_activity,
            100,
        ),
        ResponseQueueResult::Queued
    ));
    assert_eq!(last_activity.load(Ordering::Acquire), 100);
    let ResponseQueueResult::Pending(pending) = try_queue_tun_udp_response(
        &responses,
        UdpDatagram::new(server, source, b"held".as_slice()),
        &last_activity,
        110,
    ) else {
        panic!("full queue must return its uncommitted response")
    };
    assert_eq!(last_activity.load(Ordering::Acquire), 100);
    assert_eq!(&queued.recv().await.unwrap().payload[..], b"queued");
    assert!(matches!(
        try_queue_tun_udp_response(&responses, pending, &last_activity, 120),
        ResponseQueueResult::Queued
    ));
    assert_eq!(last_activity.load(Ordering::Acquire), 120);
    assert_eq!(&queued.recv().await.unwrap().payload[..], b"held");
}

#[tokio::test]
async fn dns_fast_path_allows_sixteen_concurrent_sources_and_keeps_udp_responsive() {
    const QUERY_COUNT: usize = 16;

    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let send_started = Arc::new(Notify::new());
    let send_count = Arc::new(AtomicUsize::new(0));
    let open_count = Arc::new(AtomicUsize::new(0));
    let dns_dispatcher = Arc::new(BlockingDispatcher {
        send_started,
        send_count: send_count.clone(),
        open_count: open_count.clone(),
    });
    let dns = test_runtime_dns(dns_dispatcher);
    let limits = ResourceLimits {
        packet_queue_capacity: 64,
        event_queue_capacity: 32,
        tun_max_datagram_size: TUN_MTU,
        ..ResourceLimits::default()
    };
    let runtime = TunRuntime::new(
        tun,
        limits,
        dispatcher.clone(),
        Some(dns),
        true,
        false,
        None,
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));
    let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();

    let malformed_source: SocketAddr = "192.0.2.10:11999".parse().unwrap();
    peer.send(&build_udp(malformed_source, requested_server, b"invalid"))
        .await
        .unwrap();

    for index in 0..QUERY_COUNT {
        let source = SocketAddr::new(
            Ipv4Addr::new(192, 0, 2, 10).into(),
            12_000 + u16::try_from(index).unwrap(),
        );
        let domain = format!("stall-{index}.example");
        let query = build_query(
            0x1000 + u16::try_from(index).unwrap(),
            &domain,
            QueryType::A,
        )
        .unwrap();
        peer.send(&build_udp(source, requested_server, &query))
            .await
            .unwrap();
    }
    timeout(Duration::from_secs(2), async {
        while send_count.load(Ordering::Relaxed) < QUERY_COUNT {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the DNS queries did not reach their stalled upstreams");
    assert!(dispatcher.udp_sessions.lock().unwrap().is_empty());
    assert_eq!(open_count.load(Ordering::Relaxed), QUERY_COUNT);

    let ordinary_source: SocketAddr = "192.0.2.99:13000".parse().unwrap();
    let ordinary_destination: SocketAddr = "203.0.113.30:443".parse().unwrap();
    peer.send(&build_udp(
        ordinary_source,
        ordinary_destination,
        b"still-responsive",
    ))
    .await
    .unwrap();
    let mut response = [0_u8; TUN_MTU];
    let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
        .await
        .expect("stalled DNS queries blocked ordinary UDP")
        .unwrap();
    assert_udp_response(
        &response[..size],
        ordinary_destination,
        ordinary_source,
        b"still-responsive",
    );

    assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert_eq!(open_count.load(Ordering::Relaxed), QUERY_COUNT);
    assert_eq!(send_count.load(Ordering::Relaxed), QUERY_COUNT);

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("stalled DNS tasks prevented the TUN stop barrier")
        .unwrap()
        .unwrap();
}

#[test]
fn oversized_tun_dns_response_is_dropped() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let requested_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let query = build_query(0x3456, "example.com", QueryType::A).unwrap();
    let request = UdpDatagram::new(source, requested_server, query.clone());
    let tun_mtu = 1_400;
    let ceiling =
        usize::from(DatagramSession::for_tun(source, tun_mtu).max_response_payload_size());
    assert!(complete_tun_dns_response(&request, vec![0_u8; ceiling], tun_mtu).is_some());
    assert!(complete_tun_dns_response(&request, vec![0_u8; ceiling + 1], tun_mtu).is_none());
}

#[test]
fn ipv6_tun_dns_responses_preserve_the_requested_server_and_client_endpoints() {
    let source: SocketAddr = "[2001:db8::10]:12000".parse().unwrap();
    let requested_server: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
    let query = build_query(0x4567, "example.com", QueryType::Aaaa).unwrap();
    let classified = classify_query(&query).unwrap();
    let request = UdpDatagram::new(source, requested_server, query);
    let response = complete_tun_dns_response(
        &request,
        synthesize_empty_response(&classified, 0).unwrap(),
        TUN_MTU,
    )
    .unwrap();
    assert_eq!(response.source, requested_server);
    assert_eq!(response.destination, source);
    let parsed = crate::dns::parse_response(&response.payload).unwrap();
    assert_eq!(parsed.id, classified.id);

    let servfail = tun_dns_servfail_response(&request, &classified);
    assert_eq!(servfail.source, requested_server);
    assert_eq!(servfail.destination, source);
    assert_eq!(
        u16::from_be_bytes([servfail.payload[2], servfail.payload[3]]) & 0x000f,
        2
    );
}

#[tokio::test]
async fn cancellation_interrupts_a_blocked_udp_send_and_completes_the_stop_barrier() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let send_started = Arc::new(Notify::new());
    let dispatcher = Arc::new(BlockingDispatcher {
        send_started: send_started.clone(),
        send_count: Arc::new(AtomicUsize::new(0)),
        open_count: Arc::new(AtomicUsize::new(0)),
    });
    let runtime = TunRuntime::new(
        tun,
        ResourceLimits::default(),
        dispatcher,
        None,
        true,
        false,
        None,
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));

    peer.send(&build_udp(
        "192.0.2.10:12000".parse().unwrap(),
        "198.51.100.20:53".parse().unwrap(),
        b"block",
    ))
    .await
    .unwrap();
    timeout(Duration::from_secs(2), send_started.notified())
        .await
        .expect("UDP transport send was not polled");

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("blocked UDP send prevented the TUN stop barrier")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn fresh_udp_source_beyond_the_old_sixty_four_limit_is_accepted() {
    const OLD_UDP_LIMIT: usize = 64;

    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let send_started = Arc::new(Notify::new());
    let send_count = Arc::new(AtomicUsize::new(0));
    let open_count = Arc::new(AtomicUsize::new(0));
    let dispatcher = Arc::new(BlockingDispatcher {
        send_started,
        send_count: send_count.clone(),
        open_count: open_count.clone(),
    });
    let limits = ResourceLimits {
        packet_queue_capacity: 128,
        event_queue_capacity: 128,
        tun_max_datagram_size: TUN_MTU,
        ..ResourceLimits::default()
    };
    let runtime = TunRuntime::new(tun, limits, dispatcher, None, true, false, None).unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();

    for index in 0..OLD_UDP_LIMIT {
        let source = SocketAddr::new(
            Ipv4Addr::new(192, 0, 2, 10).into(),
            12_000 + u16::try_from(index).unwrap(),
        );
        peer.send(&build_udp(source, destination, b"held"))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while open_count.load(Ordering::Acquire) <= index {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a UDP association was not opened");
    }
    assert_eq!(send_count.load(Ordering::Acquire), OLD_UDP_LIMIT);
    assert_eq!(open_count.load(Ordering::Acquire), OLD_UDP_LIMIT);

    let sixty_fifth_source: SocketAddr = "192.0.2.99:13000".parse().unwrap();
    peer.send(&build_udp(sixty_fifth_source, destination, b"accepted"))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while open_count.load(Ordering::Acquire) == OLD_UDP_LIMIT {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the sixty-fifth fresh UDP source was not accepted");
    assert_eq!(open_count.load(Ordering::Acquire), OLD_UDP_LIMIT + 1);

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("TUN runtime stop timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn queued_udp_response_is_drained_before_a_same_source_ingress_burst() {
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let dispatcher = Arc::new(ResponseFirstDispatcher {
        response: Datagram {
            remote: Destination::Ip(server),
            payload: Bytes::from_static(b"response"),
            sniffed_domain: None,
        },
    });
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    inbound_tx
        .send(UdpDatagram::new(source, server, b"next-query".as_slice()))
        .await
        .unwrap();
    let (responses_tx, mut responses_rx) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    let child = cancellation.clone();
    let task = tokio::spawn(async move {
        run_udp_association_inner(
            &mut inbound_rx,
            &UdpAssociationTaskContext {
                udp_timeout: Duration::from_secs(30),
                association_id: 1,
                source,
                responses: responses_tx,
                dispatcher,
                resource_stats: RuntimeResourceStats::new("tun_runtime_test"),
                association_clock: AssociationClock::realtime(),
                last_activity: Arc::new(AtomicU64::new(0)),
                tun_mtu: TUN_MTU,
                sniffer: None,
                cancellation: child,
            },
        )
        .await
    });

    let response = timeout(Duration::from_secs(1), responses_rx.recv())
        .await
        .expect("ready response was starved behind the same-source query")
        .expect("response channel closed");
    assert_eq!(response.source, server);
    assert_eq!(response.destination, source);
    assert_eq!(&response.payload[..], b"response");

    cancellation.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .expect("association did not stop")
        .unwrap()
        .unwrap();
    drop(inbound_tx);
}

#[tokio::test]
async fn full_udp_association_queue_does_not_block_other_sources() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
    let tun = TunIo::new(fd, crate::TunFraming::RawIp).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let blocked_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let responsive_source: SocketAddr = "192.0.2.11:12001".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let send_started = Arc::new(Notify::new());
    let dispatcher = Arc::new(SourceSelectiveDispatcher {
        blocked_source,
        send_started: send_started.clone(),
    });
    let limits = ResourceLimits {
        packet_queue_capacity: 64,
        event_queue_capacity: 64,
        tun_udp_association_queue_capacity: 2,
        tun_udp_response_queue_capacity: 4,
        tun_max_datagram_size: TUN_MTU,
        ..ResourceLimits::default()
    };
    let runtime = TunRuntime::new(tun, limits, dispatcher, None, true, false, None).unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));

    peer.send(&build_udp(blocked_source, destination, b"block"))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), send_started.notified())
        .await
        .expect("blocked association did not enter outbound send");

    for _ in 0..=limits.tun_udp_association_queue_capacity {
        peer.send(&build_udp(blocked_source, destination, b"queued"))
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }
    peer.send(&build_udp(
        responsive_source,
        destination,
        b"still-responsive",
    ))
    .await
    .unwrap();

    let mut response = [0_u8; TUN_MTU];
    let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
        .await
        .expect("a full source queue blocked another UDP association")
        .unwrap();
    assert_udp_response(
        &response[..size],
        destination,
        responsive_source,
        b"still-responsive",
    );

    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("TUN runtime stop timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blocked_udp_response_does_not_block_ingress_or_stop() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let tun = TunIo::new(
        TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
        crate::TunFraming::RawIp,
    )
    .unwrap();
    let limits = ResourceLimits {
        packet_queue_capacity: 1,
        ..ResourceLimits::default()
    };
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let first_source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let second_source: SocketAddr = "192.0.2.11:12001".parse().unwrap();
    let held = build_udp(destination, first_source, b"held");
    let held_count = fill_tun_egress(&host, &held);
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let stats = Arc::new(TunTrafficStats::default());
    let runtime = TunRuntime::new_with_stats(
        tun,
        limits,
        &test_tun_config(),
        dispatcher.clone(),
        None,
        true,
        false,
        None,
        stats.clone(),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));
    peer.send(&build_udp(first_source, destination, b"first"))
        .await
        .unwrap();
    let first_reply = timeout(
        Duration::from_secs(1),
        dispatcher.udp_response_ready.notified(),
    )
    .await;
    peer.send(&build_udp(second_source, destination, b"second"))
        .await
        .unwrap();
    let ingress_progressed = timeout(Duration::from_secs(1), async {
        while dispatcher.udp_sessions.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();

    cancellation.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .expect("full platform output prevented the TUN stop barrier")
        .unwrap()
        .unwrap();
    assert!(
        first_reply.is_ok(),
        "first source did not produce a response"
    );
    assert!(ingress_progressed, "blocked reply starved UDP ingress");
    assert_eq!(stats.snapshot().down_total, 0);
    let mut received = [0_u8; TUN_MTU];
    for _ in 0..held_count {
        let size = peer.try_recv(&mut received).unwrap();
        assert_eq!(&received[..size], held.as_slice());
    }
    assert!(
        peer.try_recv(&mut received).is_err(),
        "packet emitted after Stop"
    );
}

fn fill_tun_egress(host: &UnixDatagram, packet: &[u8]) -> usize {
    let mut count = 0;
    loop {
        match host.send(packet) {
            Ok(size) => {
                assert_eq!(size, packet.len());
                count += 1;
                assert!(count < 65_536, "local packet queue did not become full");
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::ENOBUFS) =>
            {
                return count;
            }
            Err(error) => panic!("unexpected local packet queue error: {error}"),
        }
    }
}

#[tokio::test]
async fn transient_tcp_ingress_pressure_yields_once_and_retains_the_packet() {
    let limits = ResourceLimits {
        packet_queue_capacity: 1,
        ..ResourceLimits::default()
    };
    let mut parts = NetStack::start_tcp(tun_netstack_config(limits, false)).unwrap();
    let destination = "198.51.100.20:443".parse().unwrap();
    let first = "192.0.2.20:13000".parse().unwrap();
    let second = "192.0.2.21:13001".parse().unwrap();
    parts
        .packet_sink
        .try_send(build_tcp_syn(first, destination))
        .unwrap();
    let cancellation = CancellationToken::new();
    let mut offer = Box::pin(offer_netstack_packet(
        &parts.packet_sink,
        Packet::new(build_tcp_syn(second, destination)),
        &cancellation,
    ));
    // No await has allowed the current-thread driver to drain the only slot.
    let first_poll = futures_util::poll!(offer.as_mut());
    let first_poll_pending = first_poll.is_pending();
    let first_reply = timeout(Duration::from_secs(1), parts.packet_stream.recv()).await;
    let sent = match first_poll {
        Poll::Ready(result) => result,
        Poll::Pending => offer.await,
    };
    let second_reply = if sent.is_ok() {
        timeout(Duration::from_secs(1), parts.packet_stream.recv())
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    parts.control.stop().await;
    assert!(
        first_poll_pending,
        "transient Full dropped the packet before yielding"
    );
    let first_reply = first_reply.unwrap().unwrap();
    assert_eq!(first_reply.data()[22..24], first.port().to_be_bytes());
    sent.unwrap();
    let second_reply = second_reply.expect("retained SYN never reached the stack");
    assert_eq!(second_reply.data()[22..24], second.port().to_be_bytes());
    assert_eq!(second_reply.data()[33] & 0x12, 0x12);
}

#[tokio::test]
async fn full_tcp_ingress_drops_only_that_packet_and_keeps_udp_and_dns_responsive() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let tun = Arc::new(
        TunIo::new(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            crate::TunFraming::RawIp,
        )
        .unwrap(),
    );
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let server: SocketAddr = "198.51.100.20:443".parse().unwrap();
    // Cache readable readiness before creating the spawned driver. The next
    // reader poll can then consume real packets synchronously on this thread.
    peer.send(&build_udp(source, server, b"warmup")).unwrap();
    tun.read_packet(&mut Vec::new()).await.unwrap();
    let limits = ResourceLimits {
        packet_queue_capacity: 1,
        ..ResourceLimits::default()
    };
    let mut parts = NetStack::start_tcp(tun_netstack_config(limits, false)).unwrap();
    let held_source: SocketAddr = "192.0.2.20:13000".parse().unwrap();
    let retry_source: SocketAddr = "192.0.2.21:13001".parse().unwrap();
    // There is deliberately no await from start_tcp through the first reader
    // poll: the current-thread driver cannot free this single ingress slot.
    parts
        .packet_sink
        .try_send(build_tcp_syn(held_source, server))
        .unwrap();
    let dropped = build_tcp_syn(retry_source, server);
    let ordinary = build_udp(source, server, b"responsive");
    let dns_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let query = build_query(0x2810, "responsive.example", QueryType::A).unwrap();
    let dns_packet = build_udp(source, dns_server, &query);
    for packet in [&dropped, &ordinary, &dns_packet] {
        peer.send(packet).unwrap();
    }
    let resources = RuntimeResourceStats::new("full_tcp_ingress_test");
    let traffic = Arc::new(TunTrafficStats::default());
    let dispatcher = Arc::new(MockDispatcher::default());
    let dns_dispatcher = Arc::new(DnsReplyDispatcher::default());
    let cancellation = CancellationToken::new();
    let (udp, mut ordinary_rx, mut dns_rx) = UdpIngress::new(
        UdpIngressContext {
            resources: None,
            config: test_tun_config(),
            dispatcher: dispatcher.clone(),
            dns: Some(test_runtime_dns(dns_dispatcher.clone())),
            sniffer: None,
            limits,
            resource_stats: resources.clone(),
        },
        cancellation.clone(),
    );
    let mut reader = Box::pin(tun_read_loop(
        tun,
        parts.packet_sink.clone(),
        true,
        udp,
        traffic.clone(),
        cancellation.clone(),
    ));
    let pending =
        std::future::poll_fn(|cx| Poll::Ready(reader.as_mut().poll(cx).is_pending())).await;
    // Keep the driver unscheduled through the one allowed yield. Persistent
    // Full must still leave ordinary UDP and DNS free to make progress.
    let still_pending =
        std::future::poll_fn(|cx| Poll::Ready(reader.as_mut().poll(cx).is_pending())).await;
    assert!(still_pending);
    let dropped_packets = resources.snapshot().packet_queue_drops;
    let consumed_bytes = traffic.snapshot().up_total;
    let task = tokio::spawn(reader);
    let responses = timeout(Duration::from_secs(1), async {
        (
            ordinary_rx.recv().await.unwrap(),
            dns_rx.recv().await.unwrap(),
        )
    })
    .await;
    cancellation.cancel();
    let stopped = timeout(Duration::from_secs(1), task).await;
    let driver_still_running = !parts.control.is_stopped();
    // Re-offering the dropped SYN after capacity is freed is an ordinary TCP
    // retransmission; no extra pending queue or association is required.
    let retry = if responses.is_ok() && stopped.is_ok() {
        timeout(Duration::from_secs(1), async {
            let first = parts.packet_stream.recv().await.unwrap();
            assert_eq!(first.data()[22..24], held_source.port().to_be_bytes());
            parts.packet_sink.send(dropped.clone()).await.unwrap();
            parts.packet_stream.recv().await.unwrap()
        })
        .await
        .ok()
    } else {
        None
    };
    parts.control.stop().await;
    stopped
        .expect("reader Stop waited for TCP capacity or driver shutdown")
        .unwrap()
        .unwrap();
    assert!(pending, "reader exited before its cancellation");
    assert_eq!(dropped_packets, 1);
    assert_eq!(
        consumed_bytes,
        (dropped.len() + ordinary.len() + dns_packet.len()) as u64
    );
    let (ordinary_response, dns_response) = responses.expect("TCP Full blocked UDP or DNS");
    assert_eq!(&ordinary_response.payload[..], b"responsive");
    assert_eq!(ordinary_response.source, server);
    assert_eq!(dns_response.source, dns_server);
    assert_eq!(dns_response.destination, source);
    assert_eq!(
        crate::dns::parse_response(&dns_response.payload)
            .unwrap()
            .id,
        0x2810
    );
    assert_eq!(dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert_eq!(dns_dispatcher.udp_sessions.lock().unwrap().len(), 1);
    assert!(
        driver_still_running,
        "fixture stopped TCP before reader cleanup"
    );
    let retried = retry.expect("retransmitted SYN did not resume its handshake");
    assert_eq!(retried.data()[9], 6);
    assert_eq!(retried.data()[22..24], retry_source.port().to_be_bytes());
    assert_eq!(retried.data()[33] & 0x12, 0x12);
}

#[tokio::test]
async fn tun_writer_drains_remaining_lanes_and_drops_only_invalid_datagrams() {
    let server: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    for close_ordinary in [true, false] {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let tun = Arc::new(
            TunIo::new(
                TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
                crate::TunFraming::RawIp,
            )
            .unwrap(),
        );
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let parts = NetStack::start_tcp(NetStackConfig::default()).unwrap();
        // A closed raw lane must not discard either remaining UDP lane.
        parts.control.stop().await;
        let (ordinary_tx, ordinary_rx) = mpsc::channel(3);
        let (dns_tx, dns_rx) = mpsc::channel(3);
        let remaining = if close_ordinary {
            drop(ordinary_tx);
            dns_tx
        } else {
            drop(dns_tx);
            ordinary_tx
        };
        for datagram in [
            UdpDatagram::new(server, source, Bytes::from(vec![0_u8; TUN_MTU])),
            UdpDatagram::new(
                server,
                "[2001:db8::1]:12000".parse().unwrap(),
                &b"mixed"[..],
            ),
            UdpDatagram::new(server, source, &b"valid"[..]),
        ] {
            remaining
                .try_send(QueuedUdpResponse::ordinary(datagram))
                .unwrap();
        }
        drop(remaining);
        let result = timeout(
            Duration::from_secs(1),
            tun_write_loop(
                tun,
                parts.packet_stream,
                ordinary_rx,
                dns_rx,
                TUN_MTU,
                Arc::new(TunTrafficStats::default()),
                CancellationToken::new(),
            ),
        )
        .await;
        result
            .expect("writer did not drain its remaining queue")
            .unwrap();
        let mut response = [0_u8; TUN_MTU];
        let size = timeout(Duration::from_secs(1), peer.recv(&mut response))
            .await
            .expect("valid response was discarded")
            .unwrap();
        assert_udp_response(&response[..size], server, source, b"valid");
        assert_eq!(size, 28 + b"valid".len());
        assert!(peer.try_recv(&mut response).is_err(), "response replayed");
    }
}

#[tokio::test]
async fn tun_writer_services_ready_raw_ordinary_and_dns_lanes_fairly_across_batches() {
    const PER_LANE: u8 = 9;
    let (host, peer) = UnixDatagram::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let tun = Arc::new(
        TunIo::new(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            crate::TunFraming::RawIp,
        )
        .unwrap(),
    );
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let parts = NetStack::start_tcp(NetStackConfig {
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    let ordinary_server: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let dns_server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let (ordinary_tx, ordinary_rx) = mpsc::channel(usize::from(PER_LANE));
    let (dns_tx, dns_rx) = mpsc::channel(usize::from(PER_LANE));
    for index in 0..PER_LANE {
        parts
            .packet_sink
            .send(build_icmp_echo(index, &[0, index]))
            .await
            .unwrap();
        ordinary_tx
            .try_send(QueuedUdpResponse::ordinary(UdpDatagram::new(
                ordinary_server,
                source,
                Bytes::from(vec![1, index]),
            )))
            .unwrap();
        dns_tx
            .try_send(QueuedUdpResponse::ordinary(UdpDatagram::new(
                dns_server,
                source,
                Bytes::from(vec![2, index]),
            )))
            .unwrap();
    }
    timeout(Duration::from_secs(1), async {
        while parts.stats.snapshot().icmp_replied < usize::from(PER_LANE) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("raw responses were not all ready before writer admission");
    drop((ordinary_tx, dns_tx));
    let cancellation = CancellationToken::new();
    let stats = Arc::new(TunTrafficStats::default());
    let task = tokio::spawn(tun_write_loop(
        tun,
        parts.packet_stream,
        ordinary_rx,
        dns_rx,
        TUN_MTU,
        stats.clone(),
        cancellation.clone(),
    ));
    let received = timeout(Duration::from_secs(2), async {
        let mut packets = Vec::new();
        let mut packet = [0_u8; TUN_MTU];
        for _ in 0..usize::from(PER_LANE) * 3 {
            let size = peer.recv(&mut packet).await.unwrap();
            packets.push(packet[..size].to_vec());
        }
        packets
    })
    .await;
    parts.control.stop().await;
    if received.is_err() {
        cancellation.cancel();
    }
    timeout(Duration::from_secs(1), task)
        .await
        .expect("writer did not drain its remaining lanes")
        .unwrap()
        .unwrap();
    let packets = received.expect("a ready output lane was starved");
    for (offset, packet) in packets.iter().enumerate() {
        let index = u8::try_from(offset / 3).unwrap();
        match offset % 3 {
            0 => {
                assert_eq!(packet[9], 1, "raw lane lost its turn");
                assert_eq!(packet[20], 0);
                assert_eq!(&packet[28..], &[0, index]);
            }
            1 => assert_udp_response(packet, ordinary_server, source, &[1, index]),
            _ => assert_udp_response(packet, dns_server, source, &[2, index]),
        }
    }
    assert_eq!(
        stats.snapshot().down_total,
        packets
            .iter()
            .map(|packet| packet.len() as u64)
            .sum::<u64>()
    );
    let mut packet = [0_u8; TUN_MTU];
    assert!(peer.try_recv(&mut packet).is_err(), "output replayed");
}

#[tokio::test]
async fn tun_writer_retains_dns_permit_until_platform_completion_or_cancelled_send_is_joined() {
    let server: SocketAddr = "198.51.100.20:53".parse().unwrap();
    let source: SocketAddr = "192.0.2.10:12000".parse().unwrap();
    for (cancel_send, accepted_prefix) in [(true, false), (false, false), (true, true)] {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let tun = Arc::new(
            TunIo::new(
                TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
                crate::TunFraming::RawIp,
            )
            .unwrap(),
        );
        let held = build_udp(server, source, b"held");
        let held_count = if accepted_prefix {
            // Keep a cached writable observation before filling the peer. One
            // freed packet slot will accept the ordinary prefix, not the DNS
            // suffix, when the same writer future is polled below.
            tun.write_packet(&held).await.unwrap();
            1 + fill_tun_egress(&host, &held)
        } else {
            fill_tun_egress(&host, &held)
        };
        if accepted_prefix {
            let mut removed = [0_u8; TUN_MTU];
            let size = peer.recv(&mut removed).unwrap();
            assert_eq!(&removed[..size], held.as_slice());
        }
        let parts = NetStack::start_tcp(NetStackConfig::default()).unwrap();
        let dns = test_runtime_dns(Arc::new(DnsReplyDispatcher::default()));
        let probe = observation::ResourceProbe::default();
        let permit = probe.scope_sync(|| dns.begin_query());
        let (ordinary_tx, ordinary_rx) = mpsc::channel(1);
        let (dns_tx, dns_rx) = mpsc::channel(1);
        if accepted_prefix {
            ordinary_tx
                .try_send(QueuedUdpResponse::ordinary(UdpDatagram::new(
                    server,
                    source,
                    &b"sent"[..],
                )))
                .unwrap();
        }
        dns_tx
            .try_send(QueuedUdpResponse::dns(
                UdpDatagram::new(server, source, &b"response"[..]),
                permit,
            ))
            .unwrap();
        let cancellation = CancellationToken::new();
        let stats = Arc::new(TunTrafficStats::default());
        let mut writer = Box::pin(tun_write_loop(
            tun,
            parts.packet_stream,
            ordinary_rx,
            dns_rx,
            TUN_MTU,
            stats.clone(),
            cancellation.clone(),
        ));
        let pending =
            std::future::poll_fn(|cx| Poll::Ready(writer.as_mut().poll(cx).is_pending())).await;
        let active_waiters = probe.snapshot().current(observation::ResourceKind::Waiter);
        let mut received = [0_u8; TUN_MTU];
        if cancel_send {
            cancellation.cancel();
        } else {
            // Capacity becoming available completes the very same send;
            // neither raw enqueue nor dequeue may release its permit early.
            for _ in 0..held_count {
                let size = peer.recv(&mut received).unwrap();
                assert_eq!(&received[..size], held.as_slice());
            }
            drop((ordinary_tx, dns_tx));
            parts.control.stop().await;
        }
        let joined = timeout(Duration::from_secs(1), writer).await;
        parts.control.stop().await;
        assert!(pending, "writer did not wait for platform output capacity");
        assert_eq!(active_waiters, 1, "DNS permit was released before delivery");
        joined
            .expect("writer cancellation waited for netstack stop")
            .unwrap();
        assert!(probe.snapshot().is_idle(), "writer retained a DNS permit");
        if cancel_send {
            for _ in 0..held_count - usize::from(accepted_prefix) {
                let size = peer.recv(&mut received).unwrap();
                assert_eq!(&received[..size], held.as_slice());
            }
            if accepted_prefix {
                let size = peer.recv(&mut received).unwrap();
                assert_udp_response(&received[..size], server, source, b"sent");
                assert_eq!(stats.snapshot().down_total, 32);
            } else {
                assert_eq!(stats.snapshot().down_total, 0);
            }
        } else {
            let size = peer.recv(&mut received).unwrap();
            assert_udp_response(&received[..size], server, source, b"response");
            assert_eq!(stats.snapshot().down_total, size as u64);
        }
        assert!(peer.recv(&mut received).is_err(), "response replayed");
    }
}

#[tokio::test]
async fn udp_ingress_stop_releases_associations_without_cancelling_caller() {
    let parts = NetStack::start_tcp(NetStackConfig::default()).unwrap();
    let send_started = Arc::new(Notify::new());
    let dispatcher = Arc::new(BlockingDispatcher {
        send_started: send_started.clone(),
        send_count: Arc::new(AtomicUsize::new(0)),
        open_count: Arc::new(AtomicUsize::new(0)),
    });
    let stats = RuntimeResourceStats::new("tun_runtime_test");
    let cancellation = CancellationToken::new();
    let probe = observation::ResourceProbe::default();
    let (mut udp, ordinary, dns) = UdpIngress::new(
        UdpIngressContext {
            resources: None,
            config: test_tun_config(),
            dispatcher,
            dns: None,
            sniffer: None,
            limits: ResourceLimits::default(),
            resource_stats: stats.clone(),
        },
        cancellation.clone(),
    );
    // The output consumers are already gone. Scope cleanup must still cancel
    // and join this blocked transport without stopping the caller or TCP.
    drop((ordinary, dns));
    probe.scope_sync(|| {
        udp.offer(UdpPacketView {
            source: "192.0.2.10:12000".parse().unwrap(),
            destination: "198.51.100.20:443".parse().unwrap(),
            payload: b"blocked",
        })
    });
    let started = timeout(Duration::from_secs(1), send_started.notified())
        .await
        .is_ok();
    let joined = timeout(Duration::from_secs(1), udp.stop()).await;
    let finished_within_scope = joined.is_ok();
    let netstack_was_running = !parts.control.is_stopped();
    parts.control.stop().await;
    assert!(started, "association did not enter its blocked transport");
    assert!(
        finished_within_scope,
        "UDP stop did not join the blocked transport"
    );
    assert!(
        !cancellation.is_cancelled(),
        "UDP scope cancelled its caller"
    );
    assert!(
        netstack_was_running,
        "fixture stopped netstack before UDP cleanup"
    );
    assert_eq!(stats.snapshot().udp_current, 0);
    assert_eq!(stats.snapshot().udp_peak, 1);
    assert!(
        probe.snapshot().is_idle(),
        "UDP scope returned before its tasks were joined"
    );
}

fn build_udp(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
        panic!("test helper requires IPv4");
    };
    let mut udp = vec![0_u8; 8 + payload.len()];
    udp[..2].copy_from_slice(&source.port().to_be_bytes());
    udp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    let udp_len = u16::try_from(udp.len()).unwrap();
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = transport_checksum(*source.ip(), *destination.ip(), 17, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    build_ipv4(*source.ip(), *destination.ip(), 17, &udp)
}

fn build_icmp_echo(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![0_u8; 8 + payload.len()];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&17_u16.to_be_bytes());
    icmp[6..8].copy_from_slice(&u16::from(sequence).to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let checksum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    build_ipv4(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        1,
        &icmp,
    )
}

fn build_tcp_syn(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    build_tcp_segment(source, destination, 1, 0, 0x02, &[])
}

fn build_tcp_segment(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
        panic!("test helper requires IPv4");
    };
    let mut tcp = vec![0_u8; 20 + payload.len()];
    tcp[..2].copy_from_slice(&source.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    tcp[20..].copy_from_slice(payload);
    let checksum = transport_checksum(*source.ip(), *destination.ip(), 6, &tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    build_ipv4(*source.ip(), *destination.ip(), 6, &tcp)
}

fn build_ipv4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, transport: &[u8]) -> Vec<u8> {
    let mut packet = vec![0_u8; 20 + transport.len()];
    let packet_len = u16::try_from(packet.len()).unwrap();
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(transport);
    packet
}

fn assert_udp_response(packet: &[u8], source: SocketAddr, destination: SocketAddr, payload: &[u8]) {
    assert_eq!(packet[9], 17);
    assert_eq!(
        u16::from_be_bytes(packet[20..22].try_into().unwrap()),
        source.port()
    );
    assert_eq!(
        u16::from_be_bytes(packet[22..24].try_into().unwrap()),
        destination.port()
    );
    assert_eq!(&packet[28..], payload);
}

fn transport_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    transport: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, &source.octets());
    add_bytes(&mut sum, &destination.octets());
    sum += u32::from(protocol);
    sum += u32::try_from(transport.len()).unwrap();
    add_bytes(&mut sum, transport);
    fold(sum)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, bytes);
    fold(sum)
}

fn add_bytes(sum: &mut u32, bytes: &[u8]) {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        *sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(byte) = remainder.first() {
        *sum += u32::from(*byte) << 8;
    }
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !u16::try_from(sum).unwrap();
    if checksum == 0 { u16::MAX } else { checksum }
}

#[tokio::test]
async fn configured_jumbo_mtu_reaches_platform_io_and_udp_response_budget() {
    let (host, peer) = UnixDatagram::pair().unwrap();
    // macOS defaults cap each Unix datagram below the configured jumbo MTU.
    // Increase only this pair so both injected packets and responses fit.
    socket2::SockRef::from(&peer)
        .set_send_buffer_size(32_768)
        .unwrap();
    socket2::SockRef::from(&host)
        .set_send_buffer_size(32_768)
        .unwrap();
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(65_536)
        .unwrap();
    socket2::SockRef::from(&host)
        .set_recv_buffer_size(65_536)
        .unwrap();
    host.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let config = TunConfig {
        enable: true,
        ..TunConfig::default()
    };
    let limits = ResourceLimits {
        tun_max_datagram_size: 9000,
        ..ResourceLimits::default()
    };
    let tun = TunIo::new_with_mtu(
        TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
        crate::TunFraming::RawIp,
        config.mtu,
    )
    .unwrap();
    let dispatcher = Arc::new(MockDispatcher::default());
    let runtime = TunRuntime::new_with_stats(
        tun,
        limits,
        &config,
        dispatcher.clone(),
        None,
        true,
        false,
        None,
        Arc::new(TunTrafficStats::default()),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(runtime.run(cancellation.clone()));
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let payload = vec![0x5a; 8952];
    let mut response = vec![0; 9000];
    for (source, destination) in [
        ("192.0.2.10:12000", "198.51.100.20:443"),
        ("[2001:db8::10]:12000", "[2001:db8::20]:443"),
    ] {
        let request = UdpDatagram::new(
            source.parse().unwrap(),
            destination.parse().unwrap(),
            payload.clone(),
        );
        let mut packet = Vec::new();
        encode_udp_packet_into(&request, 9000, &mut packet).unwrap();
        peer.send(&packet).await.unwrap();
        let size = timeout(Duration::from_secs(2), peer.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_packet_view(&response[..size]).unwrap();
        assert_eq!(parsed.source, request.destination);
        assert_eq!(parsed.destination, request.source);
        assert_eq!(parsed.payload, payload.as_slice());
    }
    cancellation.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let sessions = dispatcher.udp_sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.max_response_payload_size() == 8952)
    );
}

#[tokio::test]
async fn configured_udp_idle_timeout_controls_real_association_cleanup() {
    for seconds in [7, 300] {
        let tick = Arc::new(AtomicU64::new(0));
        let config = TunConfig {
            udp_timeout: Duration::from_secs(seconds),
            ..test_tun_config()
        };
        let cancellation = CancellationToken::new();
        let (mut ingress, _ordinary, _dns) = UdpIngress::new(
            UdpIngressContext {
                resources: None,
                dispatcher: Arc::new(MockDispatcher::default()),
                dns: None,
                sniffer: None,
                limits: ResourceLimits::default(),
                config,
                resource_stats: RuntimeResourceStats::new("configured_udp_idle_test"),
            },
            cancellation,
        );
        ingress.association_clock = AssociationClock::injected(tick.clone());
        let source = "192.0.2.10:12000".parse().unwrap();
        ingress.offer(UdpPacketView {
            source,
            destination: "198.51.100.20:443".parse().unwrap(),
            payload: b"queued",
        });
        tick.store(seconds - 1, Ordering::Release);
        ingress.cleanup();
        assert!(ingress.associations.contains_key(&source));
        let child = ingress.associations[&source].cancellation.clone();
        tick.store(seconds, Ordering::Release);
        ingress.cleanup();
        assert!(ingress.associations.is_empty());
        assert!(child.is_cancelled());
        ingress.stop().await;
    }
}

#[tokio::test]
async fn configured_udp_dns_targets_match_exact_endpoints_and_empty_disables_hijack() {
    let dispatcher = Arc::new(MockDispatcher::default());
    let dns = test_runtime_dns(dispatcher.clone());
    let target = "192.0.2.53:5353".parse().unwrap();
    let (mut ingress, _ordinary, _dns) = UdpIngress::new(
        UdpIngressContext {
            resources: None,
            dispatcher,
            dns: Some(dns),
            sniffer: None,
            limits: ResourceLimits::default(),
            config: TunConfig {
                dns_hijack: vec![target],
                ..test_tun_config()
            },
            resource_stats: RuntimeResourceStats::new("configured_dns_targets_test"),
        },
        CancellationToken::new(),
    );
    let first = "192.0.2.10:12000".parse().unwrap();
    ingress.offer(UdpPacketView {
        source: first,
        destination: target,
        payload: b"invalid-dns",
    });
    assert!(ingress.associations.is_empty());
    let second = "192.0.2.11:12001".parse().unwrap();
    ingress.offer(UdpPacketView {
        source: second,
        destination: "1.1.1.1:53".parse().unwrap(),
        payload: b"ordinary-udp",
    });
    assert!(ingress.associations.contains_key(&second));
    ingress.context.config.dns_hijack.clear();
    ingress.offer(UdpPacketView {
        source: first,
        destination: target,
        payload: b"ordinary-udp",
    });
    assert!(ingress.associations.contains_key(&first));
    ingress.stop().await;
}
