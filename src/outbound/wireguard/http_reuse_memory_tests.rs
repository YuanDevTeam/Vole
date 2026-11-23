//! Constructor/path proofs only: no engine, stack, packet, DNS or socket.
use super::*;
use crate::{
    config::{Config, ConnectionSettings, EgressOptions, IpVersion, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::Dispatcher,
    outbound::{ConnectorDispatcher, IpVersionConnector, SelectUpstream, SelectUpstreamMember},
    routing::GroupSelection,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn public_key() -> String {
    let secret = boringtun::x25519::StaticSecret::from(rand::random::<[u8; 32]>());
    STANDARD.encode(boringtun::x25519::PublicKey::from(&secret).as_bytes())
}

fn raw(multiple: bool) -> Value {
    // Generated only inside this memory fixture; never written or printed.
    let mut node = json!({
        "name":"memory-wireguard","type":"wireguard","ip":"10.0.0.2",
        "ipv6":"fd00::2","private-key":STANDARD.encode(rand::random::<[u8;32]>()),
        "udp":true,"mtu":1408,"reserved":[1,2,3],"persistent-keepalive":17
    });
    if multiple {
        node["peers"] = json!([
            {"server":"192.0.2.10","port":51820,"public-key":public_key(),
             "pre-shared-key":STANDARD.encode(rand::random::<[u8;32]>()),
             "allowed-ips":["0.0.0.0/0","::/0"]},
            {"server":"198.51.100.20","port":51821,"public-key":public_key(),
             "reserved":[4,5,6],"allowed-ips":["10.1.0.0/16","fd00:1::/64"]}
        ]);
    } else {
        node["server"] = json!("192.0.2.10");
        node["port"] = json!(51820);
        node["public-key"] = json!(public_key());
        node["pre-shared-key"] = json!(STANDARD.encode(rand::random::<[u8; 32]>()));
    }
    node
}

fn config(raw: Value) -> WireGuardOutboundConfig {
    let parsed = Config::parse_yaml(json!({"proxies":[raw]}).to_string().as_bytes()).unwrap();
    let ProxyProtocol::WireGuard(config) = &parsed.proxies[0].protocol else {
        panic!("expected normalized WireGuard configuration");
    };
    config.clone()
}

fn endpoint() -> ResolvedEndpoint {
    ResolvedEndpoint {
        logical_host: "192.0.2.10".into(),
        port: 51820,
        addresses: vec!["192.0.2.10:51820".parse().unwrap()],
    }
}

fn path(dialer: Dialer) -> UpstreamPath {
    UpstreamPath::direct(endpoint(), dialer)
}

fn node(config: &WireGuardOutboundConfig, path: UpstreamPath) -> WireGuardOutbound {
    WireGuardOutbound::new_with_path(config, path).unwrap()
}

fn pristine(node: &WireGuardOutbound) {
    assert!(node.current.try_lock().unwrap().is_none());
    assert_eq!(node.retired.len(), 0);
    assert!(!node.cancel.is_cancelled());
}

struct Unknown;
#[async_trait]
impl OutboundConnector for Unknown {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("a WireGuard HTTP proof must not open a stream")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("a WireGuard HTTP proof must not open a datagram path")
    }
}

#[test]
fn wireguard_single_and_multiple_peer_actual_constructors_remain_uninitialized() {
    for multiple in [false, true] {
        let config = config(raw(multiple));
        assert_eq!(config.refresh_server_ip_interval, 0);
        assert_eq!(config.peers.len(), if multiple { 2 } else { 1 });
        let node = node(&config, path(Dialer::default()));
        for _ in 0..3 {
            assert!(node.permits_http_tcp_reuse());
        }
        pristine(&node);
        let adapted = ConnectorDispatcher::new(Arc::new(node));
        assert!(Dispatcher::permits_http_tcp_reuse(&adapted));
    }
}

#[test]
fn wireguard_every_real_peer_is_checked_instead_of_representative_endpoint() {
    let mut config = config(raw(true));
    config.address = "representative.invalid".into();
    config.port = 443;
    let static_node = node(&config, path(Dialer::default()));
    assert!(
        static_node.permits_http_tcp_reuse(),
        "the actual peer graph is literal"
    );
    pristine(&static_node);
    config.address = config.peers[0].address.clone();
    config.port = config.peers[0].port;
    config.peers[1].address = "dynamic-second-peer.invalid".into();
    let dynamic = node(&config, path(Dialer::default()));
    assert!(!dynamic.permits_http_tcp_reuse());
    pristine(&dynamic);
    config.routes.retain(|(_, index)| *index == 0);
    let unrouted = node(&config, path(Dialer::default()));
    assert!(
        !unrouted.permits_http_tcp_reuse(),
        "the proof covers every configured peer"
    );
    pristine(&unrouted);
}

#[test]
fn wireguard_duplicate_key_normalization_uses_final_actual_endpoint() {
    let mut document = raw(true);
    document["peers"][1]["public-key"] = document["peers"][0]["public-key"].clone();
    for server in ["198.51.100.20", "last-declaration.invalid"] {
        document["peers"][1]["server"] = json!(server);
        let config = config(document.clone());
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].address, server);
        assert_eq!(config.peers[0].port, 51821);
        let node = node(&config, path(Dialer::default()));
        assert_eq!(node.permits_http_tcp_reuse(), server == "198.51.100.20");
        pristine(&node);
    }
}

#[test]
fn wireguard_proof_follows_actual_for_server_retargeting_for_each_peer() {
    let config = config(raw(true));
    let upstream = path(Dialer::default());
    let first = crate::outbound::server_destination(&config.peers[0].address, config.peers[0].port)
        .unwrap();
    let second =
        crate::outbound::server_destination(&config.peers[1].address, config.peers[1].port)
            .unwrap();
    assert!(matches!(
        upstream.for_server(&first, false),
        UpstreamPath::Direct { .. }
    ));
    assert!(matches!(
        upstream.for_server(&second, false),
        UpstreamPath::LazyDirect { .. }
    ));
    let node = node(&config, upstream);
    assert!(node.permits_http_tcp_reuse());
    pristine(&node);
}

#[test]
fn wireguard_literal_refresh_paths_remain_proven_without_roaming_or_resolution() {
    for refresh in [0, 1, -1, i64::MAX] {
        let mut config = config(raw(true));
        config.refresh_server_ip_interval = refresh;
        let node = node(&config, path(Dialer::default()));
        for peer in &config.peers {
            let server = crate::outbound::server_destination(&peer.address, peer.port).unwrap();
            assert!(matches!(
                node.upstream.for_server(&server, true),
                UpstreamPath::LazyDirect { .. }
            ));
        }
        assert!(node.permits_http_tcp_reuse());
        pristine(&node);
        config.peers[1].address = "refresh-second-peer.invalid".into();
        let dynamic = self::node(&config, path(Dialer::default()));
        assert!(!dynamic.permits_http_tcp_reuse());
        pristine(&dynamic);
    }
}

#[test]
fn wireguard_exact_ipv6_literal_paths_remain_uninitialized() {
    let mut document = raw(true);
    document["peers"][0]["server"] = json!("2001:db8::10");
    document["peers"][1]["server"] = json!("2001:db8::20");
    document["refresh-server-ip-interval"] = json!(1);
    let config = config(document);
    let endpoint = ResolvedEndpoint {
        logical_host: "2001:db8::10".into(),
        port: 51820,
        addresses: vec!["[2001:db8::10]:51820".parse().unwrap()],
    };
    let node = node(&config, UpstreamPath::direct(endpoint, Dialer::default()));
    assert!(node.permits_http_tcp_reuse());
    pristine(&node);
}

#[test]
fn wireguard_mismatched_prepared_paths_follow_real_literal_retargeting() {
    let mut mismatches = Vec::new();
    let mut wrong_host = endpoint();
    wrong_host.logical_host = "old-resolution.invalid".into();
    mismatches.push(wrong_host);
    let mut wrong_port = endpoint();
    wrong_port.port = 443;
    mismatches.push(wrong_port);
    let mut empty = endpoint();
    empty.addresses.clear();
    mismatches.push(empty);
    let mut wrong_ip = endpoint();
    wrong_ip.addresses[0] = "198.51.100.30:51820".parse().unwrap();
    mismatches.push(wrong_ip);
    let mut wrong_address_port = endpoint();
    wrong_address_port.addresses[0] = "192.0.2.10:443".parse().unwrap();
    mismatches.push(wrong_address_port);
    for endpoint in mismatches {
        for refresh in [0, 1] {
            let mut config = config(raw(false));
            config.refresh_server_ip_interval = refresh;
            let server =
                crate::outbound::server_destination(&config.peers[0].address, config.peers[0].port)
                    .unwrap();
            let upstream = UpstreamPath::direct(endpoint.clone(), Dialer::default());
            // The real driver discards this descriptor, keeping its same Dialer.
            assert!(matches!(
                upstream.for_server(&server, false),
                UpstreamPath::LazyDirect { .. }
            ));
            let node = node(&config, upstream);
            assert!(node.permits_http_tcp_reuse());
            pristine(&node);
        }
    }
}

#[test]
fn wireguard_ip4p_initial_and_refresh_share_actual_address_and_encoded_port() {
    let encoded = "[2001:0::1bb:c000:201]:8443".parse().unwrap();
    let physical = "192.0.2.1:443".parse().unwrap();
    for convert in [false, true] {
        let mut document = raw(false);
        document["server"] = json!("2001:0::1bb:c000:201");
        document["port"] = json!(8443);
        document["refresh-server-ip-interval"] = json!(-1);
        let config = config(document);
        let settings = ConnectionSettings {
            dialer_ip4p_convert: convert,
            ..Default::default()
        };
        let upstream = UpstreamPath::direct(
            ResolvedEndpoint {
                logical_host: config.peers[0].address.clone(),
                port: config.peers[0].port,
                addresses: vec![encoded],
            },
            Dialer::default().with_connections(settings),
        );
        let server = Destination::Ip(encoded);
        let expected = if convert { physical } else { encoded };
        let UpstreamPath::Direct { endpoint, dialer } = upstream.for_server(&server, false) else {
            panic!("initial exact literal must retain its prepared path");
        };
        assert_eq!(
            dialer.ordered_connected_addresses(&endpoint.addresses),
            [expected]
        );
        let UpstreamPath::LazyDirect { dialer } = upstream.for_server(&server, true) else {
            panic!("refresh must retain the same physical Dialer policy");
        };
        assert_eq!(dialer.connections(), settings);
        // Literal physical_address uses this same immutable conversion before
        // the ordinary second resolve in Driver::endpoint; no resolver is run.
        assert_eq!(
            dialer.connections().convert_ip4p_endpoint(encoded),
            expected
        );
        let node = node(&config, upstream);
        assert!(node.permits_http_tcp_reuse());
        pristine(&node);
    }
}

#[test]
fn wireguard_rejects_unknown_proxy_group_and_even_a_proven_tcp_parent() {
    let config = config(raw(false));
    assert!(!Unknown.permits_http_tcp_reuse());
    let unknown = node(&config, UpstreamPath::proxy(Arc::new(Unknown)));
    assert!(!unknown.permits_http_tcp_reuse());
    pristine(&unknown);
    let selection = Arc::new(GroupSelection::new(0));
    let grouped = node(
        &config,
        UpstreamPath::Group {
            server: Destination::Ip("192.0.2.10:51820".parse().unwrap()),
            group: Arc::new(SelectUpstream::new(
                selection.clone(),
                vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
            )),
            endpoint: Some(endpoint()),
            dialer: Dialer::default(),
        },
    );
    assert!(!grouped.permits_http_tcp_reuse());
    selection.store(1, std::sync::atomic::Ordering::Release);
    assert!(!grouped.permits_http_tcp_reuse());
    pristine(&grouped);
    let parent = Arc::new(node(&config, path(Dialer::default())));
    assert!(parent.permits_http_tcp_reuse());
    let child = node(&config, UpstreamPath::proxy(parent));
    assert!(
        !child.permits_http_tcp_reuse(),
        "a TCP proof cannot authorize its UDP carrier"
    );
    pristine(&child);
}

struct NeverProtect;
impl crate::dialer::SocketProtector for NeverProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("proof queries must not create sockets or invoke protect")
    }
}

#[test]
fn wireguard_preserves_physical_restrictions_and_exact_prepared_endpoints() {
    let config = config(raw(true));
    for dialer in [
        Dialer::default().with_ip_version(IpVersion::Ipv4),
        Dialer::default().with_ip_version(IpVersion::Ipv6),
        Dialer::default().with_ip_version(IpVersion::Ipv4Prefer),
        Dialer::default().with_ip_version(IpVersion::Ipv6Prefer),
        Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
        #[cfg(not(target_vendor = "apple"))]
        Dialer::default().with_mptcp(true),
        Dialer::default().with_egress(&EgressOptions {
            interface: Some("memory-interface".into()),
            ..Default::default()
        }),
        Dialer::default().with_protector(Arc::new(NeverProtect)),
    ] {
        let restricted = node(&config, path(dialer));
        assert!(!restricted.permits_http_tcp_reuse());
        pristine(&restricted);
    }
    for extra in ["198.51.100.30:51820", "192.0.2.10:51820"] {
        for refresh in [0, 1] {
            let mut config = config.clone();
            config.refresh_server_ip_interval = refresh;
            let mut multiple = endpoint();
            multiple.addresses.push(extra.parse().unwrap());
            let server = Destination::Ip("192.0.2.10:51820".parse().unwrap());
            let upstream = UpstreamPath::direct(multiple, Dialer::default());
            // Validation retains this Direct, so its non-singleton list must
            // fail even when refresh would later become a safe LazyDirect.
            assert!(matches!(
                upstream.for_server(&server, false),
                UpstreamPath::Direct { .. }
            ));
            let ambiguous = node(&config, upstream);
            assert!(!ambiguous.permits_http_tcp_reuse());
            pristine(&ambiguous);
        }
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn wireguard_dns_bound_physical_path_keeps_existing_restriction() {
    let config = config(raw(false));
    let dialer = Dialer::default()
        .for_dns_source(
            crate::dns::source::DnsBinding {
                interface: "memory-dns-interface".into(),
                interface_index: None,
            },
            "192.0.2.10:51820".parse().unwrap(),
        )
        .unwrap();
    let node = node(&config, path(dialer));
    assert!(!node.permits_http_tcp_reuse());
    pristine(&node);
}

#[test]
fn wireguard_invalid_config_never_reaches_a_static_proof() {
    let valid = config(raw(true));
    let mut empty = valid.clone();
    empty.peers.clear();
    let mut invalid_route = valid.clone();
    invalid_route.routes[0].1 = invalid_route.peers.len();
    let mut invalid_port = valid.clone();
    invalid_port.peers[1].port = 0;
    for invalid in [empty, invalid_route, invalid_port] {
        assert!(WireGuardOutbound::new_with_path(&invalid, path(Dialer::default())).is_err());
    }
}

#[test]
fn wireguard_actual_ip_version_wrapper_does_not_hide_family_policy() {
    let config = config(raw(false));
    for version in [
        IpVersion::Dual,
        IpVersion::Ipv4,
        IpVersion::Ipv6,
        IpVersion::Ipv4Prefer,
        IpVersion::Ipv6Prefer,
    ] {
        let node = Arc::new(node(&config, path(Dialer::default())));
        let wrapped = IpVersionConnector {
            inner: node.clone(),
            version,
        };
        assert_eq!(wrapped.permits_http_tcp_reuse(), version == IpVersion::Dual);
        pristine(&node);
        OutboundConnector::begin_shutdown(node.as_ref());
        assert!(!wrapped.permits_http_tcp_reuse());
    }
}

#[test]
fn wireguard_constructor_pins_crypto_route_and_local_config_without_mutating_input() {
    let mut document = raw(true);
    document["remote-dns-resolve"] = json!(true);
    document["dns"] = json!(["udp://192.0.2.53"]);
    document["refresh-server-ip-interval"] = json!(1);
    let mut input = config(document);
    assert!(!input.dns.is_empty());
    let expected = input.clone();
    let node = node(&input, path(Dialer::default()));
    assert!(node.config.as_ref() == &expected);
    input.private_key = input.peers[0].public_key.clone();
    input.peers[1].public_key = input.peers[0].public_key.clone();
    input.peers[0].pre_shared_key = None;
    input.peers[1].reserved = [7, 8, 9];
    input.peers[1].allowed_ips.clear();
    input.routes.clear();
    input.ipv4 = Some("10.9.9.9".parse().unwrap());
    input.ipv6 = None;
    input.mtu = 1280;
    input.persistent_keepalive = 0;
    input.dns.clear();
    input.refresh_server_ip_interval = -1;
    input.address = "externally-changed.invalid".into();
    input.port = 443;
    assert!(node.config.as_ref() == &expected);
    assert!(node.permits_http_tcp_reuse());
    pristine(&node);
}

#[test]
fn wireguard_owner_and_original_dialer_stop_each_revoke_static_permission() {
    let config = config(raw(true));
    for lazy in [false, true] {
        let dialer = Dialer::default();
        let upstream = if lazy {
            UpstreamPath::LazyDirect {
                dialer: dialer.clone(),
            }
        } else {
            path(dialer.clone())
        };
        let node = node(&config, upstream);
        assert!(node.permits_http_tcp_reuse());
        dialer.begin_shutdown();
        assert!(!node.permits_http_tcp_reuse());
        pristine(&node);
    }
    let node = self::node(&config, path(Dialer::default()));
    assert!(node.permits_http_tcp_reuse());
    OutboundConnector::begin_shutdown(&node);
    assert!(!node.permits_http_tcp_reuse());
    assert!(node.current.try_lock().unwrap().is_none());
}

#[tokio::test]
async fn wireguard_never_opened_shutdown_does_not_initialize_an_engine() {
    let config = config(raw(true));
    let node = node(&config, path(Dialer::default()));
    assert!(node.permits_http_tcp_reuse());
    OutboundConnector::shutdown(&node).await;
    assert!(!node.permits_http_tcp_reuse());
    assert!(node.current.try_lock().unwrap().is_none());
    assert_eq!(node.retired.len(), 0);
}
