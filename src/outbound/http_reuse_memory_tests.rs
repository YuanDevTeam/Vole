//! Structural HTTP reuse proofs only: no socket, resolver, file or runtime.
use super::*;
use crate::config::{EgressOptions, IpVersion};

fn server() -> Destination {
    Destination::Ip("192.0.2.10:8443".parse().unwrap())
}

fn endpoint() -> ResolvedEndpoint {
    ResolvedEndpoint {
        logical_host: "192.0.2.10".into(),
        port: 8443,
        addresses: vec!["192.0.2.10:8443".parse().unwrap()],
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
        panic!("a structural proof must not open a stream")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("a structural proof must not open a datagram path")
    }
}

#[test]
fn static_http_path_requires_exact_literal_endpoint() {
    assert!(
        UpstreamPath::LazyDirect {
            dialer: Dialer::default(),
        }
        .permits_static_http_reuse(&server())
    );
    assert!(
        UpstreamPath::direct(endpoint(), Dialer::default()).permits_static_http_reuse(&server())
    );
    let domain = Destination::domain("proxy.invalid", 8443).unwrap();
    assert!(
        !UpstreamPath::LazyDirect {
            dialer: Dialer::default(),
        }
        .permits_static_http_reuse(&domain)
    );
    for changed in 0..5 {
        let mut endpoint = endpoint();
        match changed {
            0 => endpoint.logical_host = "proxy.invalid".into(),
            1 => endpoint.port += 1,
            2 => endpoint.addresses.clear(),
            3 => endpoint.addresses.push("192.0.2.11:8443".parse().unwrap()),
            _ => endpoint.addresses[0] = "192.0.2.11:8443".parse().unwrap(),
        }
        assert!(
            !UpstreamPath::direct(endpoint, Dialer::default()).permits_static_http_reuse(&server())
        );
    }
    assert!(!Opaque.permits_http_tcp_reuse());
    assert!(!UpstreamPath::proxy(Arc::new(Opaque)).permits_static_http_reuse(&server()));
}

struct MustNotProtect;
impl crate::dialer::SocketProtector for MustNotProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        panic!("a structural proof must not create a physical socket")
    }
}

#[test]
fn static_http_path_preserves_physical_restrictions_and_stop() {
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
            !UpstreamPath::direct(endpoint(), dialer.clone()).permits_static_http_reuse(&server())
        );
        assert!(!UpstreamPath::LazyDirect { dialer }.permits_static_http_reuse(&server()));
    }
    let dialer = Dialer::default();
    let path = UpstreamPath::direct(endpoint(), dialer.clone());
    assert!(path.permits_static_http_reuse(&server()));
    dialer.begin_shutdown();
    assert!(!path.permits_static_http_reuse(&server()));
}

#[test]
fn static_http_path_never_samples_an_upstream_group() {
    let selection = Arc::new(GroupSelection::new(0));
    let path = UpstreamPath::Group {
        server: server(),
        group: Arc::new(SelectUpstream::new(
            selection.clone(),
            vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
        )),
        endpoint: Some(endpoint()),
        dialer: Dialer::default(),
    };
    assert!(!path.permits_static_http_reuse(&server()));
    selection.store(1, std::sync::atomic::Ordering::Release);
    assert!(!path.permits_static_http_reuse(&server()));
}

#[cfg(feature = "outbound-http")]
fn http(upstream: UpstreamPath, tls: bool) -> Arc<dyn OutboundConnector> {
    use crate::{
        config::HttpOutboundConfig, outbound::http::HttpOutbound, security::SecurityContext,
    };
    let config = HttpOutboundConfig {
        address: "192.0.2.10".into(),
        port: 8443,
        tls: tls.then(|| crate::config::TlsConfig {
            server_name: "proxy.invalid".into(),
            alpn: vec![b"http/1.1".to_vec()],
            tls13_only: false,
            required_alpn: None,
            ech: None,
            client_fingerprint: None,
            certificate: Default::default(),
            identity: None,
        }),
        auth: None,
        headers: Default::default(),
    };
    Arc::new(
        HttpOutbound::with_shared_security(&config, upstream, &SecurityContext::new(), 0, 8192)
            .unwrap(),
    )
}

#[cfg(feature = "outbound-http")]
#[test]
fn static_http_proxy_recursion_preserves_opaque_path_and_stop() {
    let dialer = Dialer::default();
    let inner = http(UpstreamPath::direct(endpoint(), dialer.clone()), true);
    let middle = http(UpstreamPath::proxy(inner.clone()), false);
    let outer = http(UpstreamPath::proxy(middle), true);
    assert!(outer.permits_http_tcp_reuse());
    assert!(ConnectorDispatcher::new(outer.clone()).permits_http_tcp_reuse());
    assert!(
        IpVersionConnector {
            inner: outer.clone(),
            version: IpVersion::Dual,
        }
        .permits_http_tcp_reuse()
    );
    for version in [
        IpVersion::Ipv4,
        IpVersion::Ipv6,
        IpVersion::Ipv4Prefer,
        IpVersion::Ipv6Prefer,
    ] {
        assert!(
            !IpVersionConnector {
                inner: outer.clone(),
                version,
            }
            .permits_http_tcp_reuse()
        );
    }
    assert!(!http(UpstreamPath::proxy(Arc::new(Opaque)), false).permits_http_tcp_reuse());
    let domain = Destination::domain("proxy.invalid", 8443).unwrap();
    assert!(!UpstreamPath::proxy(inner).permits_static_http_reuse(&domain));
    dialer.begin_shutdown();
    assert!(!outer.permits_http_tcp_reuse());
}

#[cfg(feature = "outbound-socks5")]
#[test]
fn static_socks5_plain_and_tls_share_the_connector_proof() {
    use crate::{config::Socks5OutboundConfig, outbound::Socks5Outbound};
    for tls in [false, true] {
        let config = Socks5OutboundConfig {
            address: "192.0.2.10".into(),
            port: 8443,
            username: Some("memory-user".into()),
            password: Some("memory-password".into()),
            tls: tls.then(Default::default),
        };
        let dialer = Dialer::default();
        let outbound = Socks5Outbound::new_with_path(
            &config,
            UpstreamPath::direct(endpoint(), dialer.clone()),
        )
        .unwrap();
        assert!(OutboundConnector::permits_http_tcp_reuse(&outbound));
        assert!(Dispatcher::permits_http_tcp_reuse(&outbound));
        dialer.begin_shutdown();
        assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
    }
}

#[cfg(feature = "outbound-shadowsocks")]
#[test]
fn static_shadowsocks_all_ciphers_preserve_obfs_path_and_stop_guards() {
    use crate::{
        config::{ShadowsocksCipher, ShadowsocksOutboundConfig, ShadowsocksPlugin},
        outbound::ShadowsocksOutbound,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let mut config = ShadowsocksOutboundConfig {
            address: "192.0.2.10".into(),
            port: 8443,
            cipher,
            password: STANDARD.encode(vec![7; cipher.key_len()]),
            plugin: None,
            udp_over_tcp: false,
        };
        let dialer = Dialer::default();
        let outbound = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::direct(endpoint(), dialer.clone()),
        )
        .unwrap();
        assert!(OutboundConnector::permits_http_tcp_reuse(&outbound));
        assert!(Dispatcher::permits_http_tcp_reuse(&outbound));
        config.plugin = Some(ShadowsocksPlugin::Obfs {
            tls: false,
            host: "cover.invalid".into(),
        });
        let plugin = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::direct(endpoint(), Dialer::default()),
        )
        .unwrap();
        assert!(OutboundConnector::permits_http_tcp_reuse(&plugin));
        assert!(Dispatcher::permits_http_tcp_reuse(&plugin));
        OutboundConnector::begin_shutdown(&plugin);
        assert!(!OutboundConnector::permits_http_tcp_reuse(&plugin));
        dialer.begin_shutdown();
        assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
    }
}

#[test]
fn macos_mptcp_preference_only_removes_its_own_static_path_restriction() {
    let dialer = Dialer::default().with_mptcp(true);
    assert_eq!(
        UpstreamPath::direct(endpoint(), dialer.clone()).permits_static_http_reuse(&server()),
        cfg!(target_os = "macos")
    );
    assert_eq!(
        UpstreamPath::LazyDirect { dialer }.permits_static_http_reuse(&server()),
        cfg!(target_os = "macos")
    );
    let egress = EgressOptions {
        interface: Some("memory-interface".into()),
        ..Default::default()
    };
    for restricted in [
        Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
        Dialer::default().with_ip_version(IpVersion::Ipv4),
        Dialer::default().with_protector(Arc::new(MustNotProtect)),
        Dialer::default().with_egress(&egress),
    ] {
        let dialer = restricted.with_mptcp(true);
        assert!(
            !UpstreamPath::direct(endpoint(), dialer.clone()).permits_static_http_reuse(&server())
        );
        assert!(!UpstreamPath::LazyDirect { dialer }.permits_static_http_reuse(&server()));
    }
}

#[cfg(all(feature = "outbound-shadowsocks", feature = "shadow-tls-v3"))]
#[test]
fn static_ss2022_actual_shadowtls_v3_plugin_qualifies_and_stop_revokes_without_stopping_dependency()
{
    use crate::{
        config::{
            ShadowTlsConfig, ShadowsocksCipher, ShadowsocksOutboundConfig, ShadowsocksPlugin,
        },
        outbound::ShadowsocksOutbound,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let config = ShadowsocksOutboundConfig {
            address: "192.0.2.10".into(),
            port: 8443,
            cipher,
            password: STANDARD.encode(vec![7; cipher.key_len()]),
            plugin: Some(ShadowsocksPlugin::ShadowTls(ShadowTlsConfig {
                server_name: "cover.invalid".into(),
                password: "synthetic-relay".into(),
                alpn: vec![],
                required_alpn: None,
                identity: None,
                certificate: Default::default(),
                client_fingerprint: None,
            })),
            udp_over_tcp: false,
        };
        let path = UpstreamPath::direct(endpoint(), Dialer::default());
        let outbound = ShadowsocksOutbound::new_with_path(&config, path.clone()).unwrap();
        let direct = OutboundConnector::permits_http_tcp_reuse(&outbound);
        let dispatch = Dispatcher::permits_http_tcp_reuse(&outbound);
        OutboundConnector::begin_shutdown(&outbound);
        let revoked = !OutboundConnector::permits_http_tcp_reuse(&outbound)
            && !Dispatcher::permits_http_tcp_reuse(&outbound);
        let dependency_open = path.permits_static_http_reuse(&server());
        drop(outbound);
        drop(path);
        // Actual construction and post-stop/dependency controls precede the
        // desired-positive assertion. This is policy qualification, not IO.
        assert!(revoked && dependency_open);
        assert!(
            direct && dispatch,
            "actual fixed ShadowTLS-v3 plugin was excluded"
        );
    }
}

#[cfg(feature = "outbound-shadowsocks")]
#[test]
fn static_ss2022_obfs_actual_config_requires_owned_http_reuse() {
    use crate::{
        config::{Config, ProxyProtocol, ShadowsocksCipher},
        outbound::ShadowsocksOutbound,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let mut qualifications = Vec::new();
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for mode in ["http", "tls"] {
            let value = serde_json::json!({
                "proxies": [{
                    "name": "obfs", "type": "ss", "server": "192.0.2.10", "port": 8443,
                    "cipher": cipher.as_str(), "password": STANDARD.encode(vec![7; cipher.key_len()]),
                    "plugin": "obfs", "plugin-opts": {"mode": mode, "host": "cover.invalid"}
                }],
                "rules": ["MATCH,obfs"]
            });
            let parsed = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
            let ProxyProtocol::Shadowsocks(config) = &parsed.proxies[0].protocol else {
                panic!("real SS configuration expected")
            };
            let path = UpstreamPath::direct(endpoint(), Dialer::default());
            let outbound = ShadowsocksOutbound::new_with_path(config, path.clone()).unwrap();
            qualifications.push((
                cipher,
                mode,
                OutboundConnector::permits_http_tcp_reuse(&outbound),
                Dispatcher::permits_http_tcp_reuse(&outbound),
            ));
            OutboundConnector::begin_shutdown(&outbound);
            assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
            assert!(!Dispatcher::permits_http_tcp_reuse(&outbound));
            assert!(
                path.permits_static_http_reuse(&server()),
                "node Stop must not stop its dependency"
            );
            drop(outbound);
            drop(path);

            let mut domain = config.clone();
            domain.address = "proxy.invalid".into();
            let outbound = ShadowsocksOutbound::new_with_path(
                &domain,
                UpstreamPath::LazyDirect {
                    dialer: Dialer::default(),
                },
            )
            .unwrap();
            assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
            drop(outbound);

            let mut mismatch = endpoint();
            mismatch.addresses.push("192.0.2.11:8443".parse().unwrap());
            let group = UpstreamPath::Group {
                server: server(),
                group: Arc::new(SelectUpstream::new(
                    Arc::new(GroupSelection::new(0)),
                    vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
                )),
                endpoint: Some(endpoint()),
                dialer: Dialer::default(),
            };
            for path in [
                UpstreamPath::direct(mismatch, Dialer::default()),
                UpstreamPath::proxy(Arc::new(Opaque)),
                group,
            ] {
                let outbound = ShadowsocksOutbound::new_with_path(config, path).unwrap();
                assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
            }
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
                let outbound = ShadowsocksOutbound::new_with_path(
                    config,
                    UpstreamPath::direct(endpoint(), dialer),
                )
                .unwrap();
                assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
            }
            let dialer = Dialer::default();
            let outbound = ShadowsocksOutbound::new_with_path(
                config,
                UpstreamPath::direct(endpoint(), dialer.clone()),
            )
            .unwrap();
            dialer.begin_shutdown();
            assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
            drop(outbound);
        }
    }
    // All real constructions, negative controls and Stop/dependency checks run
    // before the expected RED on the old blanket plugin exclusion.
    assert_eq!(qualifications.len(), 6);
    assert!(
        qualifications
            .iter()
            .all(|(_, _, connector, dispatcher)| *connector && *dispatcher),
        "actual Config/SS/Dispatcher obfs qualification: {qualifications:?}",
    );
}

#[cfg(feature = "outbound-shadowsocks")]
fn ss2022_v2ray_mux_memory_config(
    cipher: crate::config::ShadowsocksCipher,
    plugin: &str,
    options: serde_json::Value,
) -> crate::config::ShadowsocksOutboundConfig {
    use crate::config::{Config, ProxyProtocol};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let input = serde_json::json!({
        "proxies": [{
            "name": "mux", "type": "ss", "server": "192.0.2.10", "port": 8443,
            "cipher": cipher.as_str(), "password": STANDARD.encode(vec![7; cipher.key_len()]),
            "plugin": plugin, "plugin-opts": options
        }],
        "rules": ["MATCH,mux"]
    });
    let parsed = Config::parse_yaml(&serde_json::to_vec(&input).unwrap()).unwrap();
    let ProxyProtocol::Shadowsocks(config) = &parsed.proxies[0].protocol else {
        panic!("real SS configuration expected")
    };
    config.clone()
}

#[cfg(feature = "outbound-shadowsocks")]
#[test]
fn static_ss2022_v2ray_mux_plain_actual_config_requires_owned_http_reuse() {
    use crate::{config::ShadowsocksCipher, outbound::ShadowsocksOutbound};
    let mut qualifications = Vec::new();
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let config = ss2022_v2ray_mux_memory_config(
            cipher,
            "v2ray-plugin",
            serde_json::json!({
                "mode": "websocket", "host": "cover.invalid", "path": "/mux",
                "headers": {"X-Memory-Test": "fixed"}, "mux": true, "tls": false
            }),
        );
        let path = UpstreamPath::direct(endpoint(), Dialer::default());
        let outbound = ShadowsocksOutbound::new_with_path(&config, path.clone()).unwrap();
        qualifications.push((
            cipher,
            OutboundConnector::permits_http_tcp_reuse(&outbound),
            Dispatcher::permits_http_tcp_reuse(&outbound),
        ));
        OutboundConnector::begin_shutdown(&outbound);
        assert!(!OutboundConnector::permits_http_tcp_reuse(&outbound));
        assert!(!Dispatcher::permits_http_tcp_reuse(&outbound));
        assert!(
            path.permits_static_http_reuse(&server()),
            "node Stop stopped its dependency"
        );
        drop(outbound);
        drop(path);

        let denied = |config: &crate::config::ShadowsocksOutboundConfig, path: UpstreamPath| {
            let node = ShadowsocksOutbound::new_with_path(config, path).unwrap();
            assert!(!OutboundConnector::permits_http_tcp_reuse(&node));
            assert!(!Dispatcher::permits_http_tcp_reuse(&node));
        };
        let mut domain = config.clone();
        domain.address = "proxy.invalid".into();
        denied(
            &domain,
            UpstreamPath::LazyDirect {
                dialer: Dialer::default(),
            },
        );
        let mut mismatch = endpoint();
        mismatch.addresses.push("192.0.2.11:8443".parse().unwrap());
        denied(&config, UpstreamPath::direct(mismatch, Dialer::default()));
        denied(&config, UpstreamPath::proxy(Arc::new(Opaque)));
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
        denied(&config, group.clone());
        selection.store(1, std::sync::atomic::Ordering::Release);
        denied(&config, group);
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
            denied(&config, UpstreamPath::direct(endpoint(), dialer));
        }
        let dialer = Dialer::default();
        let node = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::direct(endpoint(), dialer.clone()),
        )
        .unwrap();
        dialer.begin_shutdown();
        assert!(!OutboundConnector::permits_http_tcp_reuse(&node));
        assert!(!Dispatcher::permits_http_tcp_reuse(&node));
    }
    // Every actual construction and negative/Stop control runs before the
    // desired positive assertion; constructor/visibility failures are not RED.
    assert_eq!(qualifications.len(), 3);
    assert!(
        qualifications
            .iter()
            .all(|(_, connector, dispatcher)| *connector && *dispatcher),
        "actual Config/SS/Dispatcher plain v2ray mux qualification: {qualifications:?}"
    );
}

#[cfg(feature = "outbound-shadowsocks")]
#[test]
fn static_ss2022_v2ray_mux_unqualified_variants_keep_one_shot() {
    use crate::{config::ShadowsocksCipher, outbound::ShadowsocksOutbound};
    let mut checked = 0;
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for (plugin, options) in [
            (
                "v2ray-plugin",
                serde_json::json!({"mode":"websocket", "mux":true, "tls":true}),
            ),
            (
                "gost-plugin",
                serde_json::json!({"mode":"websocket", "mux":true, "tls":false}),
            ),
            (
                "v2ray-plugin",
                serde_json::json!({"mode":"websocket", "mux":false, "tls":false}),
            ),
            (
                "v2ray-plugin",
                serde_json::json!({"mode":"websocket", "mux":true,
                "v2ray-http-upgrade":true}),
            ),
            (
                "v2ray-plugin",
                serde_json::json!({"mode":"websocket", "mux":true,
                "v2ray-http-upgrade":true, "v2ray-http-upgrade-fast-open":true}),
            ),
        ] {
            let config = ss2022_v2ray_mux_memory_config(cipher, plugin, options);
            let node = ShadowsocksOutbound::new_with_path(
                &config,
                UpstreamPath::direct(endpoint(), Dialer::default()),
            )
            .unwrap();
            assert!(
                !OutboundConnector::permits_http_tcp_reuse(&node),
                "{cipher:?}/{plugin}"
            );
            assert!(
                !Dispatcher::permits_http_tcp_reuse(&node),
                "{cipher:?}/{plugin}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 15);
}

#[cfg(feature = "outbound-shadowsocks")]
#[test]
fn static_ss2022_v2ray_mux_actual_early_data_path_keeps_one_shot() {
    use crate::{
        config::{ShadowsocksCipher, ShadowsocksPlugin, StreamTransport},
        outbound::ShadowsocksOutbound,
    };
    let mut observations = Vec::new();
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let config = ss2022_v2ray_mux_memory_config(
            cipher,
            "v2ray-plugin",
            serde_json::json!({"mode":"websocket", "mux":true, "tls":false,
                "path":"/memory-mux/?ed=128"}),
        );
        assert!(
            matches!(
                config.plugin.as_ref(),
                Some(ShadowsocksPlugin::WebSocket {
                    transport: StreamTransport::WebSocket {
                        max_early_data: 128,
                        ..
                    },
                    ..
                })
            ),
            "actual Config must normalize early data instead of rejecting it"
        );
        let node = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::direct(endpoint(), Dialer::default()),
        )
        .unwrap();
        observations.push((
            cipher,
            OutboundConnector::permits_http_tcp_reuse(&node),
            Dispatcher::permits_http_tcp_reuse(&node),
        ));
    }
    assert!(
        observations
            .iter()
            .all(|(_, connector, dispatcher)| !connector && !dispatcher),
        "unproven early-data factory must remain one-shot: {observations:?}"
    );
}

#[cfg(feature = "outbound-vmess")]
fn vmess_http_cover_memory_config(
    cipher: &str,
    options: serde_json::Value,
    tls: bool,
) -> crate::config::VmessOutboundConfig {
    use crate::config::{Config, ProxyProtocol};
    let value = serde_json::json!({
        "proxies": [{"name": "cover", "type": "vmess", "server": "192.0.2.10",
            "port": 8443, "uuid": "07070707-0707-0707-0707-070707070707",
            "cipher": cipher, "network": "http", "tls": tls, "http-opts": options}],
        "rules": ["MATCH,cover"]
    });
    let mut parsed = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
    let ProxyProtocol::Vmess(config) = parsed.proxies.remove(0).protocol else {
        panic!("actual normalized VMess configuration expected")
    };
    config
}

#[cfg(feature = "outbound-vmess")]
fn vmess_http_cover_memory_node(
    config: &crate::config::VmessOutboundConfig,
    path: UpstreamPath,
) -> Arc<crate::outbound::vmess::VmessOutbound> {
    Arc::new(crate::outbound::vmess::VmessOutbound::new_with_path(config, path).unwrap())
}

#[cfg(feature = "outbound-vmess")]
fn vmess_http_cover_memory_dispatch(node: &Arc<crate::outbound::vmess::VmessOutbound>) -> bool {
    Dispatcher::permits_http_tcp_reuse(&ConnectorDispatcher::new(node.clone()))
}

#[cfg(feature = "outbound-vmess")]
#[test]
fn static_vmess_http_cover_plain_singleton_actual_config_requires_reuse() {
    use crate::config::VmessTransport;
    let mut qualifications = Vec::new();
    for cipher in ["auto", "none", "aes-128-gcm", "chacha20-poly1305"] {
        for headers in [
            serde_json::json!({}),
            serde_json::json!({
                "Host": ["cover.memory.invalid"], "X-Memory": ["fixed"]
            }),
        ] {
            let config = vmess_http_cover_memory_config(
                cipher,
                serde_json::json!({"method":"GET", "path":["/memory-cover"], "headers": headers}),
                false,
            );
            let VmessTransport::Http {
                method,
                uris,
                headers,
            } = &config.transport
            else {
                panic!("normalization must produce real HTTP cover")
            };
            assert_eq!(method, "GET");
            assert_eq!(uris, &["http://192.0.2.10:8443/memory-cover".to_owned()]);
            assert!(headers.values().all(|values| values.len() == 1));
            assert!(matches!(
                &config.security,
                crate::config::SecurityConfig::None
            ));
            let path = UpstreamPath::direct(endpoint(), Dialer::default());
            let node = vmess_http_cover_memory_node(&config, path.clone());
            qualifications.push((
                cipher,
                headers.is_empty(),
                OutboundConnector::permits_http_tcp_reuse(node.as_ref()),
                vmess_http_cover_memory_dispatch(&node),
            ));
            OutboundConnector::begin_shutdown(node.as_ref());
            assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
            assert!(!vmess_http_cover_memory_dispatch(&node));
            assert!(
                path.permits_static_http_reuse(&server()),
                "node Stop must leave dependency open"
            );
            drop(node);
        }
    }
    // Collect every actual construction and run Stop controls before the
    // desired-positive assertion. A parser/build error is not the intended RED.
    assert_eq!(qualifications.len(), 8);
    assert!(
        qualifications
            .iter()
            .all(|(_, _, connector, dispatcher)| *connector && *dispatcher),
        "plain singleton actual Config/VMess/Dispatcher qualifications: {qualifications:?}"
    );
}

#[cfg(feature = "outbound-vmess")]
#[test]
fn static_vmess_http_cover_keeps_tls_choice_and_complete_path_exclusions() {
    use crate::config::VmessTransport;
    let fixed =
        serde_json::json!({"path":["/memory-cover"], "headers":{"Host":["cover.memory.invalid"]}});
    let config = vmess_http_cover_memory_config("aes-128-gcm", fixed.clone(), false);
    // Existing positive path control must not depend on the new permission.
    let mut tcp = config.clone();
    tcp.transport = VmessTransport::Tcp;
    let control =
        vmess_http_cover_memory_node(&tcp, UpstreamPath::direct(endpoint(), Dialer::default()));
    assert!(OutboundConnector::permits_http_tcp_reuse(control.as_ref()));
    assert!(vmess_http_cover_memory_dispatch(&control));
    drop(control);
    for (tls, options) in [
        (true, fixed),
        (
            false,
            serde_json::json!({"path":["/one","/two"], "headers":{"Host":["cover.memory.invalid"]}}),
        ),
        (
            false,
            serde_json::json!({"path":["/one"], "headers":{"Host":["one.memory.invalid","two.memory.invalid"]}}),
        ),
        (
            false,
            serde_json::json!({"path":["/one"], "headers":{"Host":["cover.memory.invalid"],"X-Memory":["one","two"]}}),
        ),
    ] {
        let config = vmess_http_cover_memory_config("aes-128-gcm", options, tls);
        let node = vmess_http_cover_memory_node(
            &config,
            UpstreamPath::direct(endpoint(), Dialer::default()),
        );
        assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
        assert!(!vmess_http_cover_memory_dispatch(&node));
    }
    for changed in 0..5 {
        let mut mismatch = endpoint();
        match changed {
            0 => mismatch.logical_host = "proxy.memory.invalid".into(),
            1 => mismatch.port += 1,
            2 => mismatch.addresses.clear(),
            3 => mismatch.addresses.push("192.0.2.11:8443".parse().unwrap()),
            _ => mismatch.addresses[0] = "192.0.2.11:8443".parse().unwrap(),
        }
        let node = vmess_http_cover_memory_node(
            &config,
            UpstreamPath::direct(mismatch, Dialer::default()),
        );
        assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
        assert!(!vmess_http_cover_memory_dispatch(&node));
    }
    let group = UpstreamPath::Group {
        server: server(),
        group: Arc::new(SelectUpstream::new(
            Arc::new(GroupSelection::new(0)),
            vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
        )),
        endpoint: Some(endpoint()),
        dialer: Dialer::default(),
    };
    for path in [group, UpstreamPath::proxy(Arc::new(Opaque))] {
        let node = vmess_http_cover_memory_node(&config, path);
        assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
        assert!(!vmess_http_cover_memory_dispatch(&node));
    }
    let mut domain = config.clone();
    domain.address = "proxy.memory.invalid".into();
    let node = vmess_http_cover_memory_node(
        &domain,
        UpstreamPath::LazyDirect {
            dialer: Dialer::default(),
        },
    );
    assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
    assert!(!vmess_http_cover_memory_dispatch(&node));
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
        let node = vmess_http_cover_memory_node(&config, UpstreamPath::direct(endpoint(), dialer));
        assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
        assert!(!vmess_http_cover_memory_dispatch(&node));
    }
    let dialer = Dialer::default();
    let node =
        vmess_http_cover_memory_node(&config, UpstreamPath::direct(endpoint(), dialer.clone()));
    dialer.begin_shutdown();
    assert!(!OutboundConnector::permits_http_tcp_reuse(node.as_ref()));
    assert!(!vmess_http_cover_memory_dispatch(&node));
}
