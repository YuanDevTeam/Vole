//! Real MASQUE constructor proofs only; never starts an IP engine or carrier.
use super::*;
use crate::{
    config::Config,
    dialer::{Dialer, ResolvedEndpoint, SocketProtector},
    outbound::{SelectUpstream, SelectUpstreamMember},
    routing::GroupSelection,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn config(network: MasqueNetwork) -> MasqueOutboundConfig {
    let group = boring::ec::EcGroup::from_curve_name(boring::nid::Nid::X9_62_PRIME256V1).unwrap();
    let client = boring::ec::EcKey::generate(&group).unwrap();
    let peer =
        boring::pkey::PKey::from_ec_key(boring::ec::EcKey::generate(&group).unwrap()).unwrap();
    let parsed = Config::parse_yaml(
        &serde_json::to_vec(&serde_json::json!({
            "proxies": [{
                "name": "memory", "type": "masque", "server": "192.0.2.10", "port": 443,
                "private-key": STANDARD.encode(client.private_key_to_der().unwrap()),
                "public-key": STANDARD.encode(peer.public_key_to_der().unwrap()),
                "sni": "proxy.memory.invalid", "ip": "192.0.2.2", "udp": true,
                "uri": "https://tunnel.memory.invalid/connection?policy=fixed",
                "remote-dns-resolve": true, "dns": ["tcp://192.0.2.53"],
                "network": match network {
                    MasqueNetwork::H2 => "h2",
                    MasqueNetwork::Quic => "quic",
                    MasqueNetwork::H3L4Proxy => "h3-l4proxy",
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let crate::config::ProxyProtocol::Masque(config) = &parsed.proxies[0].protocol else {
        panic!("MASQUE memory configuration")
    };
    config.clone()
}

fn direct(dialer: Dialer) -> UpstreamPath {
    UpstreamPath::LazyDirect { dialer }
}

fn node(config: &MasqueOutboundConfig, path: UpstreamPath) -> MasqueOutbound {
    MasqueOutbound::with_shared_security(config, path, &SecurityContext::new()).unwrap()
}

fn modes() -> [MasqueNetwork; 3] {
    [
        MasqueNetwork::H2,
        MasqueNetwork::Quic,
        MasqueNetwork::H3L4Proxy,
    ]
}

#[test]
fn masque_static_http_reuse_keeps_parsed_identity_and_frozen_config() {
    for network in modes() {
        let mut config = config(network);
        let expected_uri = config.uri.clone();
        let expected_sni = config.server_name.clone();
        let expected_dns = config.dns.clone();
        let expected_prefixes = config.local_prefixes;
        let expected_skip = config.skip_cert_verify;
        let outbound = node(&config, direct(Dialer::default()));
        assert!(outbound.current.try_lock().unwrap().is_none());
        assert!(outbound.remote.get().is_none());
        config.private_key.clear();
        config.public_key.clear();
        config.uri = "https://changed.memory.invalid/path".into();
        config.server_name = "changed.memory.invalid".into();
        config.local_prefixes = [None, None];
        config.remote_dns_resolve = false;
        config.dns.clear();
        config.skip_cert_verify = !expected_skip;
        assert_eq!(outbound.config.uri, expected_uri);
        assert_eq!(outbound.connection.server_name, expected_sni);
        assert_eq!(outbound.config.dns, expected_dns);
        assert_eq!(outbound.config.local_prefixes, expected_prefixes);
        assert_eq!(outbound.config.skip_cert_verify, expected_skip);
        assert!(outbound.config.remote_dns_resolve);
        assert!(outbound.connection.tls.config(false).is_ok());
        assert!(outbound.connection.tls.quiche_config(expected_sni).is_ok());
        assert!(outbound.permits_http_tcp_reuse());
        assert!(
            MasqueOutbound::with_shared_security(
                &config,
                direct(Dialer::default()),
                &SecurityContext::new(),
            )
            .is_err()
        );
        outbound.begin_shutdown();
        assert!(!outbound.permits_http_tcp_reuse());
        assert!(outbound.current.try_lock().unwrap().is_none());
        assert!(outbound.remote.get().is_none());
    }
}

#[test]
fn masque_static_http_reuse_rejects_domains_and_nonexact_prepared_endpoints() {
    for network in modes() {
        let mut config = config(network);
        config.address = "proxy.memory.invalid".into();
        let outbound = node(&config, direct(Dialer::default()));
        assert!(!outbound.permits_http_tcp_reuse());
        config.address = "192.0.2.10".into();
        for changed in 0..7 {
            let mut endpoint = ResolvedEndpoint {
                logical_host: config.address.clone(),
                port: config.port,
                addresses: vec!["192.0.2.10:443".parse().unwrap()],
            };
            match changed {
                0 => endpoint.logical_host = "other.memory.invalid".into(),
                1 => endpoint.port += 1,
                2 => endpoint.addresses.push("192.0.2.11:443".parse().unwrap()),
                3 => endpoint.addresses.clear(),
                4 => endpoint.addresses[0] = "192.0.2.11:443".parse().unwrap(),
                5 => endpoint.addresses[0] = "192.0.2.10:444".parse().unwrap(),
                _ => endpoint.logical_host = "192.0.2.11".into(),
            }
            let outbound = node(&config, UpstreamPath::direct(endpoint, Dialer::default()));
            assert!(!outbound.permits_http_tcp_reuse());
        }
        let exact = ResolvedEndpoint {
            logical_host: config.address.clone(),
            port: config.port,
            addresses: vec!["192.0.2.10:443".parse().unwrap()],
        };
        let outbound = node(&config, UpstreamPath::direct(exact, Dialer::default()));
        assert!(outbound.permits_http_tcp_reuse());
    }
}

#[test]
fn masque_static_http_reuse_observes_dependency_stop_and_constraints() {
    for network in modes() {
        let config = config(network);
        let dialer = Dialer::default();
        let outbound = node(&config, direct(dialer.clone()));
        assert!(outbound.permits_http_tcp_reuse());
        dialer.begin_shutdown();
        assert!(!outbound.permits_http_tcp_reuse());
        for dialer in [
            Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
            #[cfg(not(target_vendor = "apple"))]
            Dialer::default().with_mptcp(true),
            Dialer::default().with_ip_version(crate::config::IpVersion::Ipv4),
            Dialer::default().with_ip_version(crate::config::IpVersion::Ipv6),
            Dialer::default().with_egress(&crate::config::EgressOptions {
                interface: Some("memory-interface".into()),
                routing_mark: 0,
            }),
            Dialer::default().with_protector(Arc::new(UncalledProtector)),
        ] {
            let outbound = node(&config, direct(dialer));
            assert!(!outbound.permits_http_tcp_reuse());
        }
    }
}

struct UncalledProtector;
impl SocketProtector for UncalledProtector {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("static MASQUE proof must not protect or open a socket")
    }
}

#[test]
fn masque_static_http_reuse_never_samples_an_upstream_group() {
    for network in modes() {
        let config = config(network);
        let selection = Arc::new(GroupSelection::new(0));
        let upstream = UpstreamPath::Group {
            server: Destination::Ip("192.0.2.10:443".parse().unwrap()),
            group: Arc::new(SelectUpstream::new(
                selection.clone(),
                vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
            )),
            endpoint: None,
            dialer: Dialer::default(),
        };
        let outbound = node(&config, upstream);
        assert!(!outbound.permits_http_tcp_reuse());
        selection.store(1, std::sync::atomic::Ordering::Release);
        assert!(!outbound.permits_http_tcp_reuse());
        selection.store(0, std::sync::atomic::Ordering::Release);
        assert!(!outbound.permits_http_tcp_reuse());
    }
}

struct Opaque;
#[async_trait::async_trait]
impl OutboundConnector for Opaque {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("proof queries must not acquire opaque TCP")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("proof queries must not acquire opaque UDP")
    }
}

#[test]
fn masque_static_http_reuse_keeps_unknown_upstreams_keyless() {
    for network in modes() {
        let outbound = node(&config(network), UpstreamPath::proxy(Arc::new(Opaque)));
        assert!(!outbound.permits_http_tcp_reuse());
    }
}

#[cfg(feature = "outbound-http")]
#[test]
fn masque_static_http_reuse_never_applies_tcp_proxy_proof_to_h3_udp() {
    let proxy_config = crate::config::HttpOutboundConfig {
        address: "192.0.2.11".into(),
        port: 8080,
        tls: None,
        auth: None,
        headers: Default::default(),
    };
    let dialer = Dialer::default();
    let proxy = Arc::new(
        crate::outbound::http::HttpOutbound::with_shared_security(
            &proxy_config,
            direct(dialer.clone()),
            &SecurityContext::new(),
            0,
            8192,
        )
        .unwrap(),
    );
    assert!(proxy.permits_http_tcp_reuse());
    for network in modes() {
        let outbound = node(&config(network), UpstreamPath::proxy(proxy.clone()));
        assert_eq!(
            outbound.permits_http_tcp_reuse(),
            network == MasqueNetwork::H2
        );
    }
    // HTTP is stateless: its default hook does not stop the physical owner.
    proxy.begin_shutdown();
    assert!(proxy.permits_http_tcp_reuse());
    dialer.begin_shutdown();
    let outbound = node(&config(MasqueNetwork::H2), UpstreamPath::proxy(proxy));
    assert!(!outbound.permits_http_tcp_reuse());
}

#[test]
fn masque_static_http_reuse_covers_ipv6_literal_without_resolution() {
    for network in modes() {
        let mut config = config(network);
        config.address = "2001:db8::10".into();
        let endpoint = ResolvedEndpoint {
            logical_host: config.address.clone(),
            port: config.port,
            addresses: vec!["[2001:db8::10]:443".parse().unwrap()],
        };
        let outbound = node(&config, UpstreamPath::direct(endpoint, Dialer::default()));
        assert!(outbound.permits_http_tcp_reuse());
        assert!(outbound.current.try_lock().unwrap().is_none());
    }
}

#[test]
fn masque_static_http_reuse_recurses_real_fixed_nodes_and_observes_child_stop() {
    for inner_network in modes() {
        let child = Arc::new(node(&config(inner_network), direct(Dialer::default())));
        let parent = node(
            &config(MasqueNetwork::H2),
            UpstreamPath::proxy(child.clone()),
        );
        assert!(parent.permits_http_tcp_reuse());
        for outer_network in [MasqueNetwork::Quic, MasqueNetwork::H3L4Proxy] {
            let udp_parent = node(&config(outer_network), UpstreamPath::proxy(child.clone()));
            assert!(!udp_parent.permits_http_tcp_reuse());
        }
        child.begin_shutdown();
        assert!(!parent.permits_http_tcp_reuse());
        assert!(child.current.try_lock().unwrap().is_none());
        assert!(parent.current.try_lock().unwrap().is_none());
    }
}

#[test]
fn masque_static_http_reuse_accepts_each_configured_immutable_pin_policy() {
    for network in modes() {
        for skip in [false, true] {
            let mut config = config(network);
            config.skip_cert_verify = skip;
            let outbound = node(&config, direct(Dialer::default()));
            assert!(outbound.permits_http_tcp_reuse());
            assert_eq!(outbound.config.skip_cert_verify, skip);
            // No file/dynamic ECH field exists in this typed security factory.
            assert!(outbound.connection.tls.config(false).is_ok());
            assert!(
                outbound
                    .connection
                    .tls
                    .quiche_config("proxy.memory.invalid")
                    .is_ok()
            );
        }
    }
}
