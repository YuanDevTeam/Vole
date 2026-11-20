//! Real TUIC constructors and immutable factory proofs, without opening IO.
use super::TuicOutbound;
use crate::{
    config::{Config, EgressOptions, IpVersion, TuicOutboundConfig},
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, SelectUpstream,
        SelectUpstreamMember, UpstreamPath,
    },
    routing::GroupSelection,
    session::{Destination, StreamSession},
};
use async_trait::async_trait;
use std::{
    io,
    sync::{Arc, atomic::Ordering},
};

fn config(mode: &str, uot: bool) -> TuicOutboundConfig {
    let parsed = Config::parse_yaml(
        format!(
            "proxies:\n  - name: memory\n    type: tuic\n    server: 192.0.2.10\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000007\n    password: synthetic\n    sni: tuic.memory.invalid\n    udp-relay-mode: {mode}\n    udp-over-stream: {uot}\n"
        ).as_bytes(),
    ).unwrap();
    let crate::config::ProxyProtocol::Tuic(config) = &parsed.proxies[0].protocol else {
        panic!("TUIC memory configuration")
    };
    config.clone()
}

fn endpoint() -> ResolvedEndpoint {
    ResolvedEndpoint {
        logical_host: "192.0.2.10".into(),
        port: 443,
        addresses: vec!["192.0.2.10:443".parse().unwrap()],
    }
}

fn lazy(dialer: Dialer) -> UpstreamPath {
    UpstreamPath::LazyDirect { dialer }
}

fn node(config: &TuicOutboundConfig, upstream: UpstreamPath) -> TuicOutbound {
    TuicOutbound::new_with_path(config, upstream).unwrap()
}

#[test]
fn tuic_real_constructor_proves_literal_and_explicit_ip_for_all_udp_modes() {
    for mode in ["native", "quic"] {
        for uot in [false, true] {
            for explicit_ip in [false, true] {
                let mut config = config(mode, uot);
                if explicit_ip {
                    config.address = "logical.memory.invalid".into();
                    config.ip = Some("192.0.2.10".into());
                }
                for upstream in [
                    lazy(Dialer::default()),
                    UpstreamPath::direct(endpoint(), Dialer::default()),
                ] {
                    let outbound = node(&config, upstream);
                    assert!(
                        outbound.permits_http_tcp_reuse(),
                        "{mode}/{uot}/{explicit_ip}"
                    );
                    outbound.begin_shutdown();
                    assert!(!outbound.permits_http_tcp_reuse());
                }
            }
            let mut ipv6 = config(mode, uot);
            ipv6.address = "2001:db8::10".into();
            assert!(node(&ipv6, lazy(Dialer::default())).permits_http_tcp_reuse());
        }
    }
}

#[test]
fn tuic_real_constructor_rejects_dynamic_or_mismatched_physical_endpoints() {
    for mode in ["native", "quic"] {
        for uot in [false, true] {
            let baseline = config(mode, uot);
            let mut domain = baseline.clone();
            domain.address = "dynamic.memory.invalid".into();
            assert!(!node(&domain, lazy(Dialer::default())).permits_http_tcp_reuse());
            for changed in 0..5 {
                let mut peer = endpoint();
                match changed {
                    0 => peer.logical_host = "dynamic.memory.invalid".into(),
                    1 => peer.port += 1,
                    2 => peer.addresses.clear(),
                    3 => peer.addresses.push("192.0.2.11:443".parse().unwrap()),
                    _ => peer.addresses[0] = "192.0.2.11:443".parse().unwrap(),
                }
                assert!(
                    !node(&baseline, UpstreamPath::direct(peer, Dialer::default()))
                        .permits_http_tcp_reuse()
                );
            }
        }
    }
}

// This unknown dependency supplies no capability. Neither method may be called
// by the structural query; no test substitutes a true connector/TLS proof.
struct Opaque;
#[async_trait]
impl OutboundConnector for Opaque {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("structural TUIC proof must not open an upstream stream")
    }

    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("structural TUIC proof must not open an upstream datagram")
    }
}

#[test]
fn tuic_groups_and_even_a_real_static_tcp_proxy_do_not_prove_direct_udp() {
    for mode in ["native", "quic"] {
        for uot in [false, true] {
            let config = config(mode, uot);
            let selection = Arc::new(GroupSelection::new(0));
            let group = UpstreamPath::Group {
                server: Destination::Ip("192.0.2.10:443".parse().unwrap()),
                group: Arc::new(SelectUpstream::new(
                    selection.clone(),
                    vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
                )),
                endpoint: Some(endpoint()),
                dialer: Dialer::default(),
            };
            let grouped = node(&config, group);
            assert!(!grouped.permits_http_tcp_reuse());
            selection.store(1, Ordering::Release);
            assert!(!grouped.permits_http_tcp_reuse());
            assert!(!Opaque.permits_http_tcp_reuse());
            assert!(!node(&config, UpstreamPath::proxy(Arc::new(Opaque))).permits_http_tcp_reuse());

            let inner = Arc::new(node(&config, lazy(Dialer::default())));
            assert!(inner.permits_http_tcp_reuse());
            // A real, eligible TUIC TCP connector still cannot donate proof
            // about the Proxy variant's physical UDP factory.
            assert!(!node(&config, UpstreamPath::proxy(inner)).permits_http_tcp_reuse());
        }
    }
}

struct MustNotProtect;
impl crate::dialer::SocketProtector for MustNotProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("structural TUIC proof must not allocate a socket")
    }
}

#[test]
fn tuic_preserves_actual_dialer_protection_binding_family_and_stop() {
    let egress = EgressOptions {
        interface: Some("memory-interface".into()),
        ..Default::default()
    };
    for mode in ["native", "quic"] {
        for uot in [false, true] {
            let config = config(mode, uot);
            for dialer in [
                Dialer::default().with_ip_version(IpVersion::Ipv4),
                Dialer::default().with_ip_version(IpVersion::Ipv6),
                Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
                Dialer::default().with_protector(Arc::new(MustNotProtect)),
                Dialer::default().with_egress(&egress),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                Dialer::default()
                    .for_dns_source(
                        crate::dns::source::DnsBinding {
                            interface: Arc::from("memory-interface"),
                            interface_index: None,
                        },
                        "192.0.2.10:443".parse().unwrap(),
                    )
                    .unwrap(),
            ] {
                assert!(!node(&config, lazy(dialer.clone())).permits_http_tcp_reuse());
                assert!(
                    !node(&config, UpstreamPath::direct(endpoint(), dialer))
                        .permits_http_tcp_reuse()
                );
            }
            let dialer = Dialer::default();
            let first = node(&config, lazy(dialer.clone()));
            let second = node(&config, UpstreamPath::direct(endpoint(), dialer.clone()));
            assert!(first.permits_http_tcp_reuse() && second.permits_http_tcp_reuse());
            dialer.begin_shutdown();
            assert!(!first.permits_http_tcp_reuse() && !second.permits_http_tcp_reuse());
            assert!(!node(&config, lazy(dialer)).permits_http_tcp_reuse());
        }
    }
}

#[test]
fn tuic_keeps_the_existing_macos_mptcp_preference_rule() {
    for mode in ["native", "quic"] {
        for uot in [false, true] {
            let config = config(mode, uot);
            let dialer = Dialer::default().with_mptcp(true);
            for upstream in [
                lazy(dialer.clone()),
                UpstreamPath::direct(endpoint(), dialer),
            ] {
                assert_eq!(
                    node(&config, upstream).permits_http_tcp_reuse(),
                    cfg!(target_os = "macos")
                );
            }
        }
    }
}

#[cfg(feature = "outbound-socks5")]
#[test]
fn an_actual_static_tcp_chain_inherits_tuic_proof_and_stop_revokes_it() {
    let parsed = Config::parse_yaml(
        b"proxies: [{name: memory, type: socks5, server: 192.0.2.20, port: 1080}]",
    )
    .unwrap();
    let crate::config::ProxyProtocol::Socks5(socks) = &parsed.proxies[0].protocol else {
        panic!("SOCKS5 memory configuration")
    };
    for mode in ["native", "quic"] {
        for uot in [false, true] {
            let inner = Arc::new(node(&config(mode, uot), lazy(Dialer::default())));
            let outer = crate::outbound::Socks5Outbound::new_with_path(
                socks,
                UpstreamPath::proxy(inner.clone()),
            )
            .unwrap();
            assert!(inner.permits_http_tcp_reuse());
            assert!(outer.permits_http_tcp_reuse());
            inner.begin_shutdown();
            assert!(!outer.permits_http_tcp_reuse());
        }
    }
}
