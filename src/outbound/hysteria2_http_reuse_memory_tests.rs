//! Construct production Hysteria2 outbounds and query proofs without opening IO.
//! Synthetic PEM is generated in memory; no socket, resolver or identity file.
use super::*;
use crate::config::{Config, EgressOptions, IpVersion};

fn server() -> Destination {
    Destination::Ip("192.0.2.10:443".parse().unwrap())
}

fn endpoint() -> ResolvedEndpoint {
    ResolvedEndpoint {
        logical_host: "192.0.2.10".into(),
        port: 443,
        addresses: vec!["192.0.2.10:443".parse().unwrap()],
    }
}

fn direct() -> UpstreamPath {
    UpstreamPath::LazyDirect {
        dialer: Dialer::default(),
    }
}

// A positive TCP capability deliberately does not prove this connector's UDP
// relay. Any attempted IO makes the structural fixture fail immediately.
struct TcpOnly;
#[async_trait]
impl OutboundConnector for TcpOnly {
    fn permits_http_tcp_reuse(&self) -> bool {
        true
    }
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("a structural query must not open a stream")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("a TCP proof must not authorize a UDP carrier")
    }
}

struct UnknownUpstream;
#[async_trait]
impl OutboundConnector for UnknownUpstream {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("a static query must not invoke an unknown stream connector")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("a static query must not invoke an unknown datagram connector")
    }
}

fn group() -> UpstreamPath {
    UpstreamPath::Group {
        server: server(),
        group: Arc::new(SelectUpstream::new(
            Arc::new(GroupSelection::new(0)),
            vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
        )),
        endpoint: Some(endpoint()),
        dialer: Dialer::default(),
    }
}

#[test]
fn static_direct_http_carrier_requires_the_exact_literal_physical_endpoint() {
    assert!(direct().permits_static_direct_http_reuse(&server()));
    assert!(
        UpstreamPath::direct(endpoint(), Dialer::default())
            .permits_static_direct_http_reuse(&server())
    );
    assert!(
        !direct()
            .permits_static_direct_http_reuse(&Destination::domain("quic.invalid", 443).unwrap())
    );
    for changed in 0..5 {
        let mut peer = endpoint();
        match changed {
            0 => peer.logical_host = "quic.invalid".into(),
            1 => peer.port += 1,
            2 => peer.addresses.clear(),
            3 => peer.addresses.push("192.0.2.11:443".parse().unwrap()),
            _ => peer.addresses[0] = "192.0.2.11:443".parse().unwrap(),
        }
        assert!(
            !UpstreamPath::direct(peer, Dialer::default())
                .permits_static_direct_http_reuse(&server())
        );
    }
    let proxy = UpstreamPath::proxy(Arc::new(TcpOnly));
    assert!(proxy.permits_static_http_reuse(&server()));
    assert!(!proxy.permits_static_direct_http_reuse(&server()));
    assert!(!group().permits_static_direct_http_reuse(&server()));
}

struct MustNotProtect;
impl crate::dialer::SocketProtector for MustNotProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("a structural query must not allocate a physical socket")
    }
}

#[test]
fn static_direct_http_carrier_preserves_dialer_restrictions_and_stop() {
    let egress = EgressOptions {
        interface: Some("memory-interface".into()),
        ..Default::default()
    };
    for dialer in [
        #[cfg(not(target_os = "macos"))]
        Dialer::default().with_mptcp(true),
        Dialer::default().with_ip_version(IpVersion::Ipv4),
        Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
        Dialer::default().with_protector(Arc::new(MustNotProtect)),
        Dialer::default().with_egress(&egress),
    ] {
        assert!(
            !UpstreamPath::direct(endpoint(), dialer.clone())
                .permits_static_direct_http_reuse(&server())
        );
        assert!(!UpstreamPath::LazyDirect { dialer }.permits_static_direct_http_reuse(&server()));
    }
    let dialer = Dialer::default();
    let path = UpstreamPath::direct(endpoint(), dialer.clone());
    assert!(path.permits_static_direct_http_reuse(&server()));
    dialer.begin_shutdown();
    assert!(!path.permits_static_direct_http_reuse(&server()));
}

fn inline_identity() -> crate::config::TlsIdentityPem {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let generated =
        rcgen::generate_simple_self_signed(vec!["memory-client.invalid".into()]).unwrap();
    crate::config::TlsIdentityPem {
        certificate: format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(generated.cert.der())
        ),
        private_key: format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.signing_key.serialize_der())
        ),
        origin: None,
    }
}

#[cfg(feature = "outbound-hysteria2")]
fn hysteria2_config(fields: &str) -> crate::config::Hysteria2OutboundConfig {
    let config = Config::parse_yaml(
        format!(
            "proxies:\n  - name: quic\n    type: hysteria2\n    server: 192.0.2.10\n    port: 443\n    password: synthetic\n    sni: quic.invalid\n{fields}"
        )
        .as_bytes(),
    )
    .unwrap();
    let crate::config::ProxyProtocol::Hysteria2(config) = &config.proxies[0].protocol else {
        panic!("Hysteria2 fixture configuration")
    };
    config.as_ref().clone()
}

#[cfg(feature = "outbound-hysteria2")]
fn hysteria2(
    config: &crate::config::Hysteria2OutboundConfig,
    upstream: UpstreamPath,
) -> super::super::hysteria2::Hysteria2Outbound {
    super::super::hysteria2::Hysteria2Outbound::new_with_path(config, upstream).unwrap()
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
fn hysteria2_static_http_reuse_uses_the_real_constructor_and_node_stop() {
    for fields in [
        "",
        "    up: 2000\n    down: 2000\n",
        "    up: 2000\n    down: 2000\n    obfs: salamander\n    obfs-password: synthetic-obfs\n",
    ] {
        let config = hysteria2_config(fields);
        for upstream in [
            direct(),
            UpstreamPath::direct(endpoint(), Dialer::default()),
        ] {
            let outbound = hysteria2(&config, upstream);
            assert!(outbound.permits_http_tcp_reuse());
            outbound.begin_shutdown();
            assert!(!outbound.permits_http_tcp_reuse());
        }
    }
    let mut config = hysteria2_config("");
    config.tls.identity = Some(inline_identity());
    assert!(hysteria2(&config, direct()).permits_http_tcp_reuse());
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
fn hysteria2_static_http_reuse_rejects_dynamic_discovery_and_dependencies() {
    for fields in [
        "    ports: '443,8443'\n",
        "    realm-opts: {enable: true, server-url: 'http://control.invalid', realm-id: synthetic, stun-servers: ['192.0.2.30:3478']}\n",
        "    ech-opts: {enable: true}\n",
    ] {
        assert!(!hysteria2(&hysteria2_config(fields), direct()).permits_http_tcp_reuse());
    }
    let mut domain = hysteria2_config("");
    domain.address = "quic.invalid".into();
    assert!(!hysteria2(&domain, direct()).permits_http_tcp_reuse());
    let config = hysteria2_config("");
    assert!(!UnknownUpstream.permits_http_tcp_reuse());
    for upstream in [
        UpstreamPath::proxy(Arc::new(TcpOnly)),
        UpstreamPath::proxy(Arc::new(UnknownUpstream)),
        group(),
    ] {
        assert!(!hysteria2(&config, upstream).permits_http_tcp_reuse());
    }
    let dialer = Dialer::default();
    let outbound = hysteria2(
        &config,
        UpstreamPath::LazyDirect {
            dialer: dialer.clone(),
        },
    );
    assert!(outbound.permits_http_tcp_reuse());
    dialer.begin_shutdown();
    assert!(!outbound.permits_http_tcp_reuse());
}
