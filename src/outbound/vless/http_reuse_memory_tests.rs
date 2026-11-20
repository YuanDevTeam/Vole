//! Actual VLESS constructors and static proofs only; never open a stream.
use super::*;
use crate::{
    config::{Config, IpVersion, ProxyProtocol, XHttpVersion},
    routing::GroupSelection,
    session::Destination,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn base() -> Value {
    json!({"name":"memory-vless","type":"vless","server":"192.0.2.10","port":443,
        "uuid":"09090909-0909-0909-0909-090909090909"})
}

fn reality(mut node: Value) -> Value {
    node["tls"] = json!(true);
    node["servername"] = json!("proxy.invalid");
    node["client-fingerprint"] = json!("chrome");
    // Synthetic public bytes only, never an actual server's identity.
    node["reality-opts"] = json!({"public-key":URL_SAFE_NO_PAD.encode([9_u8;32]),
        "short-id":"01020304"});
    node
}

fn jls(mut node: Value) -> Value {
    node["tls"] = json!(true);
    node["servername"] = json!("proxy.invalid");
    node["client-fingerprint"] = json!("chrome");
    node["jls-opts"] = json!({"username":"memory-user","password":"memory-password"});
    node
}

fn vision() -> Value {
    let mut node = reality(base());
    node["flow"] = json!("xtls-rprx-vision");
    node
}

fn xhttp(reality_security: bool, version: &str, mode: &str) -> Value {
    let mut node = if reality_security {
        reality(base())
    } else {
        base()
    };
    node["tls"] = json!(true);
    node["servername"] = json!("proxy.invalid");
    node["network"] = json!("xhttp");
    node["alpn"] = json!([version]);
    node["xhttp-opts"] = json!({"mode":mode,"path":"/memory/"});
    node
}

fn config(node: Value) -> VlessOutboundConfig {
    let config = Config::parse_yaml(json!({"proxies":[node]}).to_string().as_bytes()).unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        panic!("expected normalized VLESS configuration");
    };
    config.clone()
}

fn path(dialer: Dialer) -> UpstreamPath {
    UpstreamPath::direct(
        ResolvedEndpoint {
            logical_host: "192.0.2.10".into(),
            port: 443,
            addresses: vec!["192.0.2.10:443".parse().unwrap()],
        },
        dialer,
    )
}

fn node(raw: Value, upstream: UpstreamPath) -> VlessOutbound {
    VlessOutbound::new_with_path(&config(raw), upstream).unwrap()
}

fn capable(node: &VlessOutbound) -> bool {
    OutboundConnector::permits_http_tcp_reuse(node)
}

struct Unknown;
#[async_trait]
impl OutboundConnector for Unknown {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("static VLESS HTTP proof must not open a stream")
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("static VLESS HTTP proof must not open a datagram transport")
    }
}

#[test]
fn static_vless_actual_constructors_cover_three_matrix_paths_and_stop() {
    for raw in [
        vision(),
        xhttp(true, "h2", "stream-one"),
        xhttp(false, "h3", "stream-one"),
    ] {
        let config = config(raw);
        let node = VlessOutbound::new_with_shared_security(
            &config,
            path(Dialer::default()),
            None,
            &SecurityContext::new(),
            0,
            VlessResourceLimits::new(65536, 16384, 16384),
        )
        .unwrap();
        assert!(capable(&node));
        assert!(Dispatcher::permits_http_tcp_reuse(&node));
        assert_eq!(node.tasks.len(), 0);
        if matches!(&config.security, crate::config::SecurityConfig::Reality(_)) {
            assert!(
                !node.upload.security.permits_static_http_reuse(),
                "the shared VMess/Trojan helper must not gain REALITY permission"
            );
        }
        OutboundConnector::begin_shutdown(&node);
        assert!(!capable(&node));
    }
}

#[test]
fn static_vless_proof_is_not_limited_to_benchmark_modes_or_security_names() {
    let mut standard_tcp = base();
    standard_tcp["tls"] = json!(true);
    standard_tcp["servername"] = json!("proxy.invalid");
    let mut plain_h1 = xhttp(false, "http/1.1", "stream-one");
    plain_h1["tls"] = json!(false);
    plain_h1.as_object_mut().unwrap().remove("servername");
    for raw in [
        base(),
        standard_tcp,
        reality(base()),
        plain_h1,
        xhttp(true, "h2", "packet-up"),
        xhttp(false, "h2", "stream-up"),
        xhttp(false, "h3", "packet-up"),
    ] {
        let node = node(raw, path(Dialer::default()));
        assert!(capable(&node));
    }
}

#[test]
fn actual_xhttp_versions_cover_implicit_and_explicit_download_legs() {
    for version in ["http/1.1", "h2", "h3"] {
        for mode in ["packet-up", "stream-up"] {
            let mut raw = xhttp(false, version, mode);
            let implicit = node(raw.clone(), path(Dialer::default()));
            assert!(capable(&implicit));
            assert!(implicit.download.is_none());
            assert_eq!(implicit.tasks.len(), 0);

            raw["xhttp-opts"]["download-settings"] = json!({});
            let config = config(raw);
            let explicit = VlessOutbound::new_with_paths(
                &config,
                path(Dialer::default()),
                Some(path(Dialer::default())),
            )
            .unwrap();
            assert!(capable(&explicit));
            assert!(explicit.download.is_some());
            assert_eq!(explicit.tasks.len(), 0);
        }
    }
}

#[test]
fn vless_h3_uses_actual_xhttp_version_not_tcp_placeholder_or_parent_tcp_proof() {
    let parent = Arc::new(node(vision(), path(Dialer::default())));
    assert!(capable(&parent));
    let h2 = node(
        xhttp(true, "h2", "stream-one"),
        UpstreamPath::proxy(parent.clone()),
    );
    assert!(capable(&h2));
    let h3 = node(
        xhttp(false, "h3", "stream-one"),
        UpstreamPath::proxy(parent),
    );
    assert!(matches!(&h3.transport, StreamTransport::Tcp));
    assert_eq!(
        h3.xhttp.as_ref().unwrap().http_version(),
        XHttpVersion::Http3
    );
    assert!(
        !capable(&h3),
        "a TCP proxy proof cannot prove its UDP carrier"
    );
}

#[test]
fn every_static_download_leg_qualifies_but_dynamic_path_or_security_does_not() {
    let mut raw = xhttp(true, "h2", "packet-up");
    raw["xhttp-opts"]["download-settings"] = json!({});
    let split_config = config(raw.clone());
    let node = VlessOutbound::new_with_paths(
        &split_config,
        path(Dialer::default()),
        Some(path(Dialer::default())),
    )
    .unwrap();
    assert!(capable(&node));
    let upload = node.xhttp.as_ref().unwrap();
    let download = &node.download.as_ref().unwrap().xhttp;
    assert!(upload.uses_active_h2_reuse());
    assert!(download.uses_active_h2_reuse());
    assert!(capable(&node));
    assert!(upload.uses_active_h2_reuse());
    assert!(download.uses_active_h2_reuse());

    let unknown_download = VlessOutbound::new_with_paths(
        &split_config,
        path(Dialer::default()),
        Some(UpstreamPath::proxy(Arc::new(Unknown))),
    )
    .unwrap();
    assert!(!capable(&unknown_download));
    let mut dynamic = xhttp(false, "h2", "packet-up");
    dynamic["xhttp-opts"]["download-settings"] = json!({"ech-opts":{"enable":true}});
    let dynamic = VlessOutbound::new_with_paths(
        &config(dynamic),
        path(Dialer::default()),
        Some(path(Dialer::default())),
    )
    .unwrap();
    assert!(!capable(&dynamic));
    raw["xhttp-opts"]["download-settings"] = json!({"server":"download.invalid"});
    let domain_download = VlessOutbound::new_with_paths(
        &config(raw),
        path(Dialer::default()),
        Some(UpstreamPath::LazyDirect {
            dialer: Dialer::default(),
        }),
    )
    .unwrap();
    assert!(!capable(&domain_download));
}

#[test]
fn actual_download_h3_version_requires_its_own_direct_udp_path() {
    let mut raw = xhttp(false, "h2", "packet-up");
    raw["xhttp-opts"]["download-settings"] = json!({"alpn":["h3"]});
    let config = config(raw);
    let direct = VlessOutbound::new_with_paths(
        &config,
        path(Dialer::default()),
        Some(path(Dialer::default())),
    )
    .unwrap();
    assert_eq!(
        direct.xhttp.as_ref().unwrap().http_version(),
        XHttpVersion::Http2
    );
    assert_eq!(
        direct.download.as_ref().unwrap().xhttp.http_version(),
        XHttpVersion::Http3
    );
    assert!(capable(&direct));
    let parent = Arc::new(node(vision(), path(Dialer::default())));
    assert!(capable(&parent));
    let proxied_download = VlessOutbound::new_with_paths(
        &config,
        path(Dialer::default()),
        Some(UpstreamPath::proxy(parent)),
    )
    .unwrap();
    assert!(!capable(&proxied_download));
}

#[test]
fn actual_upload_and_download_xhttp_owner_stop_each_revoke_permission() {
    let mut raw = xhttp(false, "h2", "packet-up");
    raw["xhttp-opts"]["download-settings"] = json!({});
    for stop_download in [false, true] {
        let config = config(raw.clone());
        let node = VlessOutbound::new_with_paths(
            &config,
            path(Dialer::default()),
            Some(path(Dialer::default())),
        )
        .unwrap();
        assert!(capable(&node));
        let owner = if stop_download {
            &node.download.as_ref().unwrap().xhttp
        } else {
            node.xhttp.as_ref().unwrap()
        };
        owner.begin_stop();
        assert!(!node.cancellation.is_cancelled());
        assert!(!capable(&node));
    }
}

fn with_owned_encryption(mut raw: Value, appearance: &str, rtt: &str) -> Value {
    raw["encryption"] = json!(format!(
        "mlkem768x25519plus.{appearance}.{rtt}.{}",
        URL_SAFE_NO_PAD.encode([9_u8; 32])
    ));
    raw
}

fn encryption_cases(appearances: &[&str]) -> Vec<Value> {
    let mut cases = Vec::new();
    for appearance in appearances {
        for rtt in ["1rtt", "0rtt"] {
            for enabled_vision in [false, true] {
                let mut raw = base();
                if enabled_vision {
                    raw["flow"] = json!("xtls-rprx-vision");
                }
                cases.push(with_owned_encryption(raw, appearance, rtt));
            }
        }
    }
    cases
}

#[test]
fn static_vless_rejects_dynamic_ech_without_static_identity() {
    let mut dynamic = xhttp(false, "h3", "stream-one");
    dynamic["ech-opts"] = json!({"enable":true});
    assert!(!capable(&node(dynamic, path(Dialer::default()))));
}

#[test]
fn static_encrypted_vless_actual_clients_qualify_without_io() {
    for raw in encryption_cases(&["native", "xorpub", "random"]) {
        let outbound = node(raw, path(Dialer::default()));
        let client = outbound
            .encryption
            .as_ref()
            .expect("actual encryption client");
        assert!(client.permits_http_tcp_reuse());
        assert!(capable(&outbound));
        assert!(Dispatcher::permits_http_tcp_reuse(&outbound));
        assert_eq!(outbound.tasks.len(), 0);
    }
}

#[test]
fn static_encrypted_vless_actual_client_and_node_stop_revoke_qualification() {
    for raw in encryption_cases(&["native", "xorpub", "random"]) {
        let stopped_client = node(raw.clone(), path(Dialer::default()));
        let before_client = capable(&stopped_client);
        let actual_client = stopped_client.encryption.is_some();
        if let Some(client) = &stopped_client.encryption {
            client.close();
        }
        let node_still_open = !stopped_client.cancellation.is_cancelled();
        let after_client = capable(&stopped_client);
        let client_tasks = stopped_client.tasks.len();
        drop(stopped_client);
        let stopped_node = node(raw, path(Dialer::default()));
        let before_node = capable(&stopped_node);
        OutboundConnector::begin_shutdown(&stopped_node);
        let after_node = capable(&stopped_node);
        let node_tasks = stopped_node.tasks.len();
        drop(stopped_node);
        assert!(actual_client && node_still_open);
        assert_eq!((client_tasks, node_tasks), (0, 0));
        assert!(before_client && before_node);
        assert!(!after_client && !after_node);
    }
}

#[test]
fn static_encrypted_vless_keeps_all_physical_and_dependency_restrictions() {
    for raw in encryption_cases(&["native", "xorpub", "random"]) {
        let unknown = node(raw.clone(), UpstreamPath::proxy(Arc::new(Unknown)));
        let unknown_permitted = capable(&unknown);
        drop(unknown);
        let mut restricted = Vec::new();
        for dialer in [
            Dialer::default().with_ip_version(IpVersion::Ipv4),
            Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
            #[cfg(not(target_os = "macos"))]
            Dialer::default().with_mptcp(true),
        ] {
            let outbound = node(raw.clone(), path(dialer));
            restricted.push(capable(&outbound));
            drop(outbound);
        }
        let group = UpstreamPath::Group {
            server: Destination::Ip("192.0.2.10:443".parse().unwrap()),
            group: Arc::new(crate::outbound::SelectUpstream::new(
                Arc::new(GroupSelection::new(0)),
                vec![crate::outbound::SelectUpstreamMember::Direct],
            )),
            endpoint: None,
            dialer: Dialer::default(),
        };
        let grouped = node(raw.clone(), group);
        let grouped_permitted = capable(&grouped);
        drop(grouped);
        let dialer = Dialer::default();
        let stopped = node(raw, path(dialer.clone()));
        let before_stop = capable(&stopped);
        dialer.begin_shutdown();
        let after_stop = capable(&stopped);
        drop(stopped);
        assert!(!unknown_permitted && !grouped_permitted);
        assert!(restricted.iter().all(|permitted| !permitted));
        assert!(before_stop);
        assert!(!after_stop);
    }
}

#[test]
fn static_random_vless_each_actual_upstream_dependency_stop_revokes_child_proof() {
    for rtt in ["1rtt", "0rtt"] {
        for stop_download in [false, true] {
            for stop_client in [false, true] {
                let parent_raw = with_owned_encryption(base(), "random", rtt);
                let upload = Arc::new(node(parent_raw.clone(), path(Dialer::default())));
                let download = Arc::new(node(parent_raw, path(Dialer::default())));
                let mut raw = with_owned_encryption(xhttp(false, "h2", "packet-up"), "random", rtt);
                raw["xhttp-opts"]["download-settings"] = json!({});
                let child = VlessOutbound::new_with_paths(
                    &config(raw),
                    UpstreamPath::proxy(upload.clone()),
                    Some(UpstreamPath::proxy(download.clone())),
                )
                .unwrap();
                let before = capable(&upload) && capable(&download) && capable(&child);
                let stopped = if stop_download { &download } else { &upload };
                let unaffected = if stop_download { &upload } else { &download };
                if stop_client {
                    stopped.encryption.as_ref().unwrap().close();
                } else {
                    OutboundConnector::begin_shutdown(stopped.as_ref());
                }
                let dependency_revoked = !capable(stopped) && capable(unaffected);
                let child_revoked = !capable(&child);
                let child_owner_open = !child.cancellation.is_cancelled();
                let client_close_keeps_parent_owner_open =
                    !stop_client || !stopped.cancellation.is_cancelled();
                let tasks = child.tasks.len() + upload.tasks.len() + download.tasks.len();
                drop(child);
                drop(upload);
                drop(download);
                assert!(
                    before,
                    "invalid control: actual Random dependency did not qualify"
                );
                assert!(child_owner_open && client_close_keeps_parent_owner_open);
                assert_eq!(tasks, 0);
                assert!(dependency_revoked && child_revoked);
            }
        }
    }
}

#[test]
fn static_encrypted_vless_checks_each_download_path_and_owner() {
    for appearance in ["native", "xorpub", "random"] {
        for rtt in ["1rtt", "0rtt"] {
            let mut raw = with_owned_encryption(xhttp(false, "h2", "packet-up"), appearance, rtt);
            raw["xhttp-opts"]["download-settings"] = json!({});
            let selected = config(raw.clone());
            let direct = || path(Dialer::default());
            let make = |selected: &VlessOutboundConfig, download: UpstreamPath| {
                VlessOutbound::new_with_paths(selected, direct(), Some(download)).unwrap()
            };
            for stop_download in [false, true] {
                let outbound = make(&selected, direct());
                let upload = outbound.xhttp.as_ref().unwrap();
                let download = &outbound.download.as_ref().unwrap().xhttp;
                let private_pool = || {
                    (
                        upload.uses_active_h2_reuse(),
                        download.uses_active_h2_reuse(),
                    )
                };
                let before = private_pool();
                assert!(capable(&outbound));
                assert_eq!(private_pool(), before);
                if stop_download {
                    download.begin_stop();
                } else {
                    upload.begin_stop();
                }
                assert!(!capable(&outbound));
            }
            let unknown = make(&selected, UpstreamPath::proxy(Arc::new(Unknown)));
            assert!(!capable(&unknown));
            let mut dynamic_upload = raw.clone();
            dynamic_upload["ech-opts"] = json!({"enable":true});
            raw["xhttp-opts"]["download-settings"] = json!({"ech-opts":{"enable":true}});
            for dynamic in [dynamic_upload, raw] {
                assert!(!capable(&make(&config(dynamic), direct())));
            }
        }
    }
}

#[test]
fn static_vless_preserves_upstream_and_physical_restrictions() {
    for raw in [
        vision(),
        jls(base()),
        jls(xhttp(false, "http/1.1", "packet-up")),
        jls(xhttp(false, "h2", "stream-one")),
        xhttp(true, "h2", "stream-one"),
        xhttp(false, "h3", "stream-one"),
    ] {
        assert!(!capable(&node(
            raw.clone(),
            UpstreamPath::proxy(Arc::new(Unknown))
        )));
        for dialer in [
            Dialer::default().with_ip_version(IpVersion::Ipv4),
            Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
            #[cfg(not(target_os = "macos"))]
            Dialer::default().with_mptcp(true),
        ] {
            assert!(!capable(&node(raw.clone(), path(dialer))));
        }
        let dialer = Dialer::default();
        let stopped = node(raw, path(dialer.clone()));
        assert!(capable(&stopped));
        dialer.begin_shutdown();
        assert!(!capable(&stopped));
    }
    let group = UpstreamPath::Group {
        server: Destination::Ip("192.0.2.10:443".parse().unwrap()),
        group: Arc::new(crate::outbound::SelectUpstream::new(
            Arc::new(GroupSelection::new(0)),
            vec![crate::outbound::SelectUpstreamMember::Direct],
        )),
        endpoint: None,
        dialer: Dialer::default(),
    };
    assert!(!capable(&node(vision(), group)));
}

#[test]
fn business_http_proof_does_not_expand_xhttp_private_active_pool_qualification() {
    let h2 = node(xhttp(true, "h2", "stream-one"), path(Dialer::default()));
    assert!(capable(&h2));
    assert!(!h2.xhttp.as_ref().unwrap().uses_active_h2_reuse());
    let parent = Arc::new(node(vision(), path(Dialer::default())));
    let mut raw = xhttp(true, "h2", "packet-up");
    raw["xhttp-opts"]["download-settings"] = json!({});
    let config = config(raw);
    let split = VlessOutbound::new_with_paths(
        &config,
        UpstreamPath::proxy(parent.clone()),
        Some(UpstreamPath::proxy(parent)),
    )
    .unwrap();
    assert!(capable(&split));
    assert!(!split.xhttp.as_ref().unwrap().uses_active_h2_reuse());
    assert!(
        !split
            .download
            .as_ref()
            .unwrap()
            .xhttp
            .uses_active_h2_reuse()
    );
}

#[test]
fn static_vless_jls_actual_factories_keep_shared_security_keyless_and_stop() {
    let mut cases = vec![jls(base())];
    for network in ["ws", "grpc"] {
        let mut raw = jls(base());
        raw["network"] = json!(network);
        cases.push(raw);
    }
    for version in ["http/1.1", "h2"] {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let raw = jls(xhttp(false, version, mode));
            cases.push(raw.clone());
            if mode != "stream-one" {
                let mut split = raw;
                split["xhttp-opts"]["download-settings"] = json!({
                    "jls-opts":{"username":"other-memory-user","password":"other-memory-password"}
                });
                cases.push(split);
            }
        }
    }
    for raw in cases {
        for named_profile in [false, true] {
            let mut raw = raw.clone();
            if !named_profile {
                raw.as_object_mut().unwrap().remove("client-fingerprint");
            }
            let config = config(raw);
            let outbound = VlessOutbound::new_with_shared_security(
                &config,
                path(Dialer::default()),
                config.download().map(|_| path(Dialer::default())),
                &SecurityContext::new(),
                0,
                VlessResourceLimits::new(65536, 16384, 16384),
            )
            .unwrap();
            assert!(capable(&outbound));
            assert!(Dispatcher::permits_http_tcp_reuse(&outbound));
            assert!(!outbound.upload.security.permits_static_http_reuse());
            if let Some(download) = &outbound.download {
                assert!(!download.transport.security.permits_static_http_reuse());
            }
            assert_eq!(outbound.tasks.len(), 0);
            OutboundConnector::begin_shutdown(&outbound);
            assert!(!capable(&outbound));
        }
    }
}

#[test]
fn static_vless_jls_requires_actual_clients_for_both_marked_legs() {
    let mut raw = jls(xhttp(false, "h2", "packet-up"));
    raw["xhttp-opts"]["download-settings"] = json!({});
    let split = config(raw);
    for replace_download in [false, true] {
        for standard_client in [false, true] {
            let mut outbound = VlessOutbound::new_with_paths(
                &split,
                path(Dialer::default()),
                Some(path(Dialer::default())),
            )
            .unwrap();
            assert!(capable(&outbound));
            let replacement_config = if standard_client {
                config(xhttp(false, "h2", "stream-one")).security
            } else {
                crate::config::SecurityConfig::None
            };
            let replacement = SecurityClient::from_security(&replacement_config).unwrap();
            assert!(replacement.permits_static_http_reuse());
            if replace_download {
                outbound.download.as_mut().unwrap().transport.security = replacement;
            } else {
                outbound.upload.security = replacement;
            }
            assert!(
                !capable(&outbound),
                "a config marker cannot prove a different backend"
            );
        }
        let mut outbound = VlessOutbound::new_with_paths(
            &split,
            path(Dialer::default()),
            Some(path(Dialer::default())),
        )
        .unwrap();
        if replace_download {
            outbound
                .download
                .as_mut()
                .unwrap()
                .transport
                .http_reuse_security = HttpReuseSecurity::Unproven;
        } else {
            outbound.upload.http_reuse_security = HttpReuseSecurity::Unproven;
        }
        assert!(
            !capable(&outbound),
            "an actual JLS backend cannot override an unproven leg"
        );
    }
    let outbound = node(jls(base()), path(Dialer::default()));
    assert!(!outbound.upload.permits_static_http_reuse(true));
}

#[test]
fn static_vless_jls_checks_each_download_path_and_owner() {
    let mut raw = jls(xhttp(false, "http/1.1", "packet-up"));
    raw["xhttp-opts"]["download-settings"] = json!({});
    let split = config(raw.clone());
    for stop_download in [false, true] {
        let outbound = VlessOutbound::new_with_paths(
            &split,
            path(Dialer::default()),
            Some(path(Dialer::default())),
        )
        .unwrap();
        assert!(capable(&outbound));
        let owner = if stop_download {
            &outbound.download.as_ref().unwrap().xhttp
        } else {
            outbound.xhttp.as_ref().unwrap()
        };
        owner.begin_stop();
        assert!(!outbound.cancellation.is_cancelled());
        assert!(!capable(&outbound));
    }
    for stop_download in [false, true] {
        let upload_dialer = Dialer::default();
        let download_dialer = Dialer::default();
        let outbound = VlessOutbound::new_with_paths(
            &split,
            path(upload_dialer.clone()),
            Some(path(download_dialer.clone())),
        )
        .unwrap();
        assert!(capable(&outbound));
        if stop_download {
            download_dialer.begin_shutdown();
        } else {
            upload_dialer.begin_shutdown();
        }
        assert!(!outbound.cancellation.is_cancelled());
        assert!(!capable(&outbound));
    }
    for restricted_download in [false, true] {
        for restricted_dialer in [
            Dialer::default().with_ip_version(IpVersion::Ipv4),
            Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
            #[cfg(not(target_os = "macos"))]
            Dialer::default().with_mptcp(true),
        ] {
            let upload = path(if restricted_download {
                Dialer::default()
            } else {
                restricted_dialer.clone()
            });
            let download = path(if restricted_download {
                restricted_dialer
            } else {
                Dialer::default()
            });
            let outbound = VlessOutbound::new_with_paths(&split, upload, Some(download)).unwrap();
            assert!(!capable(&outbound));
        }
    }
    let unknown = VlessOutbound::new_with_paths(
        &split,
        path(Dialer::default()),
        Some(UpstreamPath::proxy(Arc::new(Unknown))),
    )
    .unwrap();
    assert!(!capable(&unknown));
    raw["xhttp-opts"]["download-settings"] = json!({"server":"download.invalid"});
    let domain = VlessOutbound::new_with_paths(
        &config(raw),
        path(Dialer::default()),
        Some(UpstreamPath::LazyDirect {
            dialer: Dialer::default(),
        }),
    )
    .unwrap();
    assert!(!capable(&domain));
}

#[test]
fn static_vless_jls_does_not_change_private_physical_pool_qualification() {
    for version in ["http/1.1", "h2"] {
        let one = node(
            jls(xhttp(false, version, "stream-one")),
            path(Dialer::default()),
        );
        assert!(capable(&one));
        assert!(!one.xhttp.as_ref().unwrap().uses_active_h2_reuse());
        let mut raw = jls(xhttp(false, version, "packet-up"));
        raw["xhttp-opts"]["download-settings"] = json!({});
        let split = node(raw, path(Dialer::default()));
        assert!(capable(&split));
        let expected = version == "h2";
        assert_eq!(
            split.xhttp.as_ref().unwrap().uses_active_h2_reuse(),
            expected
        );
        assert_eq!(
            split
                .download
                .as_ref()
                .unwrap()
                .xhttp
                .uses_active_h2_reuse(),
            expected
        );
    }
}

#[test]
fn static_vless_jls_invalid_credentials_never_construct_a_capable_node() {
    let mut config = config(jls(base()));
    let crate::config::SecurityConfig::Jls(identity) = &mut config.security else {
        panic!("expected JLS");
    };
    identity.password.clear();
    assert!(SecurityClient::from_security(&config.security).is_err());
    assert!(VlessOutbound::new_with_path(&config, path(Dialer::default())).is_err());
}

#[test]
fn macos_mptcp_preference_preserves_the_actual_vless_static_tcp_proof() {
    let mut raw = base();
    raw["mptcp"] = json!(true);
    let parsed =
        Config::parse_yaml(json!({"proxies": [raw.clone()]}).to_string().as_bytes()).unwrap();
    let proxy = &parsed.proxies[0];
    let requested = proxy.mptcp;
    let ProxyProtocol::Vless(config) = &proxy.protocol else {
        panic!("expected the normalized VLESS protocol");
    };
    let dialer = Dialer::default().with_mptcp(requested);
    let configured = VlessOutbound::new_with_path(config, path(dialer.clone())).unwrap();
    let before = capable(&configured);
    let dispatcher_before = Dispatcher::permits_http_tcp_reuse(&configured);
    let tasks = configured.tasks.len();
    dialer.begin_shutdown();
    let after = capable(&configured);
    drop(configured);
    let ordinary = node(base(), path(Dialer::default()));
    let ordinary_permitted = capable(&ordinary);
    drop(ordinary);
    assert!(requested && parsed.proxies[0].mptcp);
    assert!(ordinary_permitted);
    assert_eq!(tasks, 0);
    assert_eq!(before, cfg!(target_os = "macos"));
    assert_eq!(dispatcher_before, before);
    assert!(!after);

    for restricted in [
        Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
        Dialer::default().with_ip_version(IpVersion::Ipv4),
        Dialer::default().with_ip_version(IpVersion::Ipv6),
        Dialer::default().with_egress(&crate::config::EgressOptions {
            interface: Some("memory-interface".into()),
            ..Default::default()
        }),
    ] {
        let outbound = node(raw.clone(), path(restricted.with_mptcp(true)));
        let permitted = capable(&outbound);
        let tasks = outbound.tasks.len();
        drop(outbound);
        assert_eq!(tasks, 0);
        assert!(
            !permitted,
            "a configured MPTCP preference must not bypass physical restrictions"
        );
    }
}
