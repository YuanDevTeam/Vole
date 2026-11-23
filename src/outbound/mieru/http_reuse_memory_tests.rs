//! Query real Mieru constructors without opening a carrier, socket or resolver.
use super::*;
use crate::{
    config::{Config, EgressOptions, IpVersion, MieruHandshake, MieruMultiplexing},
    dialer::{Dialer, ResolvedEndpoint},
    outbound::{SelectUpstream, SelectUpstreamMember},
    routing::GroupSelection,
};
use std::sync::Arc;

fn server() -> Destination {
    Destination::Ip("192.0.2.10:443".parse().unwrap())
}
fn direct(dialer: Dialer) -> UpstreamPath {
    UpstreamPath::LazyDirect { dialer }
}
fn endpoint() -> ResolvedEndpoint {
    ResolvedEndpoint {
        logical_host: "192.0.2.10".into(),
        port: 443,
        addresses: vec!["192.0.2.10:443".parse().unwrap()],
    }
}
fn config(transport: &str) -> MieruOutboundConfig {
    let parsed = Config::parse_yaml(
        format!(
            "proxies:\n  - name: memory\n    type: mieru\n    server: 192.0.2.10\n    port: 443\n    username: synthetic-user\n    password: synthetic-password\n    transport: {transport}\n    udp: true\n"
        ).as_bytes(),
    ).unwrap();
    let crate::config::ProxyProtocol::Mieru(config) = &parsed.proxies[0].protocol else {
        panic!("Mieru memory configuration")
    };
    config.clone()
}
fn outbound(config: &MieruOutboundConfig, path: UpstreamPath) -> MieruOutbound {
    MieruOutbound::new(config, path, 32 * 1024).unwrap()
}

#[test]
fn mieru_real_factory_static_path_keeps_fixed_pattern_and_mode_identity() {
    // Mux policy controls carrier allocation; a held business stream retains
    // the same factory, target and cancellation owner in every mode.
    for transport in ["TCP", "UDP"] {
        for multiplexing in [
            MieruMultiplexing::Off,
            MieruMultiplexing::Low,
            MieruMultiplexing::Middle,
            MieruMultiplexing::High,
        ] {
            for handshake in [MieruHandshake::Standard, MieruHandshake::NoWait] {
                for pattern in [None, Some("CAc=".to_owned())] {
                    let mut config = config(transport);
                    config.multiplexing = multiplexing;
                    config.handshake_mode = handshake;
                    config.traffic_pattern = pattern;
                    let node = outbound(&config, direct(Dialer::default()));
                    assert!(node.permits_http_tcp_reuse());
                    node.begin_shutdown();
                    assert!(!node.permits_http_tcp_reuse());
                }
            }
        }
        assert!(
            outbound(
                &config(transport),
                UpstreamPath::direct(endpoint(), Dialer::default())
            )
            .permits_http_tcp_reuse()
        );
    }
}

struct Opaque;
#[async_trait]
impl OutboundConnector for Opaque {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("structural proof must not open opaque IO")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("structural proof must not open opaque datagrams")
    }
}

struct MustNotProtect;
impl crate::dialer::SocketProtector for MustNotProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("structural proof must not allocate a physical socket")
    }
}

#[test]
fn mieru_factory_rejects_endpoint_selection_groups_and_stopped_dependencies() {
    for transport in ["TCP", "UDP"] {
        let baseline = config(transport);
        let mut range = baseline.clone();
        range.port_end += 1;
        assert!(!outbound(&range, direct(Dialer::default())).permits_http_tcp_reuse());
        let mut named = baseline.clone();
        named.address = "dynamic.memory.invalid".into();
        assert!(!outbound(&named, direct(Dialer::default())).permits_http_tcp_reuse());
        let mut mismatch = endpoint();
        mismatch.addresses.push("192.0.2.11:443".parse().unwrap());
        assert!(
            !outbound(&baseline, UpstreamPath::direct(mismatch, Dialer::default()))
                .permits_http_tcp_reuse()
        );
        let selection = Arc::new(GroupSelection::new(0));
        let group = UpstreamPath::Group {
            server: server(),
            group: Arc::new(SelectUpstream::new(
                selection.clone(),
                vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
            )),
            endpoint: Some(endpoint()),
            dialer: Dialer::default(),
        };
        let grouped = outbound(&baseline, group);
        assert!(!grouped.permits_http_tcp_reuse());
        selection.store(1, std::sync::atomic::Ordering::Release);
        assert!(!grouped.permits_http_tcp_reuse());
        assert!(
            !outbound(&baseline, UpstreamPath::proxy(Arc::new(Opaque))).permits_http_tcp_reuse()
        );
        let egress = EgressOptions {
            interface: Some("memory-interface".into()),
            ..Default::default()
        };
        for dialer in [
            #[cfg(not(target_vendor = "apple"))]
            Dialer::default().with_mptcp(true),
            Dialer::default().with_ip_version(IpVersion::Ipv4),
            Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
            Dialer::default().with_protector(Arc::new(MustNotProtect)),
            Dialer::default().with_egress(&egress),
        ] {
            assert!(!outbound(&baseline, direct(dialer)).permits_http_tcp_reuse());
        }
        let dialer = Dialer::default();
        let node = outbound(&baseline, direct(dialer.clone()));
        assert!(node.permits_http_tcp_reuse());
        dialer.begin_shutdown();
        assert!(!node.permits_http_tcp_reuse());
    }
}

#[cfg(feature = "outbound-socks5")]
#[test]
fn mieru_tcp_graph_proof_does_not_authorize_the_same_proxied_udp_carrier() {
    let parsed = Config::parse_yaml(
        b"proxies: [{name: upstream, type: socks5, server: 192.0.2.20, port: 1080, udp: true}]",
    )
    .unwrap();
    let crate::config::ProxyProtocol::Socks5(config) = &parsed.proxies[0].protocol else {
        panic!("SOCKS5 memory upstream")
    };
    let upstream = Arc::new(
        crate::outbound::Socks5Outbound::new_with_path(config, direct(Dialer::default())).unwrap(),
    );
    assert!(OutboundConnector::permits_http_tcp_reuse(upstream.as_ref()));
    assert!(
        outbound(&self::config("TCP"), UpstreamPath::proxy(upstream.clone()))
            .permits_http_tcp_reuse()
    );
    assert!(
        !outbound(&self::config("UDP"), UpstreamPath::proxy(upstream)).permits_http_tcp_reuse()
    );
}
