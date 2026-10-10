//! Local, deterministic fixtures for the shared route/upstream group boundary.
use super::*;
use crate::{config::ProxyId, dialer::SystemResolver};
use async_trait::async_trait;
use std::sync::{Mutex, atomic::Ordering};

#[derive(Default)]
struct RecordingResolver {
    hosts: Mutex<Vec<(String, u16)>>,
    fail_host: Option<&'static str>,
}

#[async_trait]
impl Resolver for RecordingResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        self.hosts.lock().unwrap().push((host.to_owned(), port));
        if self.fail_host == Some(host) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "fixture DNS failure",
            ));
        }
        Ok(ResolvedEndpoint {
            logical_host: host.to_owned(),
            port,
            addresses: vec![
                SocketAddr::new("192.0.2.1".parse().unwrap(), port),
                SocketAddr::new("2001:db8::1".parse().unwrap(), port),
            ],
        })
    }
}

fn grouped_config(members: &str) -> String {
    format!(
        r#"mixed-port: 18080
authentication: [u:p]
ipv6: false
proxies:
  - {{name: child, type: socks5, server: child.invalid, port: 1080, udp: true, dialer-proxy: outer}}
  - {{name: root, type: socks5, server: root.invalid, port: 1081}}
proxy-groups:
  - {{name: outer, type: select, proxies: [inner, REJECT]}}
  - {{name: inner, type: select, proxies: [{members}]}}
rules: ['MATCH,child']
"#
    )
}

#[tokio::test]
async fn group_preparation_is_lazy_and_releases_registration_on_drop() {
    let directory = tempfile::tempdir().unwrap();
    let manager = GeoDataManager::open(directory.path(), Duration::from_secs(86400)).unwrap();
    let resolver = RecordingResolver {
        fail_host: Some("child.invalid"),
        ..Default::default()
    };
    for members in ["root, DIRECT", "root, REJECT"] {
        let config = Config::parse_yaml(grouped_config(members).as_bytes()).unwrap();
        let prepared = PreparedCore::prepare_config(
            config,
            manager.clone(),
            &resolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(resolver.hosts.lock().unwrap().is_empty());
        assert!(
            prepared
                .endpoints
                .iter()
                .all(|entry| entry.upload.is_none())
        );
        drop(prepared);
    }
}

#[cfg(all(feature = "outbound-vless", feature = "outbound-socks5"))]
#[tokio::test]
async fn possible_direct_vless_defers_both_independent_legs() {
    let yaml = grouped_config("root, DIRECT").replace(
        "{name: child, type: socks5, server: child.invalid, port: 1080, udp: true, dialer-proxy: outer}",
        r#"name: child
    type: vless
    server: child.invalid
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    network: xhttp
    dialer-proxy: outer
    xhttp-opts:
      download-settings:
        server: download.invalid
        port: 8443"#,
    );
    for direct in [true, false] {
        let yaml = if direct {
            yaml.clone()
        } else {
            yaml.replace("root, DIRECT", "root, REJECT")
        };
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        let child = ProxyId::new(0).unwrap();
        assert!(prepared.endpoint(child).is_none());
        assert!(prepared.download_endpoint(child).is_none());
        assert!(resolver.hosts.lock().unwrap().is_empty());
        let graph = prepared.build_proxy_graph(Dialer::default()).unwrap();
        assert_eq!(graph.len(), 2);
    }
}

#[cfg(feature = "outbound-socks5")]
#[tokio::test]
async fn config_sized_group_graph_builds_and_drops_without_cycles_or_recursion() {
    let mut yaml = grouped_config("root");
    yaml = yaml.replace("[inner, REJECT]", "[g0]");
    yaml.push_str("# large, flat YAML with deep logical dependencies\n");
    let mut groups = String::new();
    for index in 0..3000 {
        let next = if index == 2999 {
            "DIRECT".to_owned()
        } else {
            format!("g{}", index + 1)
        };
        groups.push_str(&format!(
            "  - {{name: g{index}, type: select, proxies: [{next}]}}\n"
        ));
    }
    yaml = yaml.replace("rules:", &format!("{groups}rules:"));
    assert!(yaml.len() < 256 * 1024);
    let prepared = PreparedCore::prepare(
        yaml.as_bytes(),
        &RecordingResolver::default(),
        ResourceLimits::default(),
    )
    .await
    .unwrap();
    let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
    let nodes = parts
        .proxy_graph
        .nodes
        .iter()
        .map(Arc::downgrade)
        .collect::<Vec<_>>();
    let selections = parts
        .proxy_graph
        .selections
        .iter()
        .map(Arc::downgrade)
        .collect::<Vec<_>>();
    let group_nodes = parts
        .proxy_graph
        .lifecycle_order
        .iter()
        .filter_map(|target| match target {
            BuiltRouteTarget::Group(group) => Some(Arc::downgrade(group)),
            _ => None,
        })
        .collect::<Vec<_>>();
    parts.proxy_graph.shutdown().await;
    drop(parts);
    assert!(nodes.iter().all(|node| node.upgrade().is_none()));
    assert!(
        selections
            .iter()
            .all(|selection| selection.upgrade().is_none())
    );
    assert!(group_nodes.iter().all(|group| group.upgrade().is_none()));
}

#[cfg(feature = "outbound-socks5")]
#[cfg(feature = "inbound-http")]
#[tokio::test]
async fn group_start_failure_and_repeated_stop_release_ports_and_graph_owners() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = occupied.local_addr().unwrap();
    let controller_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let controller = controller_reservation.local_addr().unwrap();
    drop(controller_reservation);
    let yaml = format!(
        "{}\nexternal-controller: {controller}\nsecret: fixture-token\n",
        grouped_config("root, DIRECT").replacen(
            "mixed-port: 18080",
            &format!("mixed-port: {}", http.port()),
            1
        )
    );
    let prepared = PreparedCore::prepare(
        yaml.as_bytes(),
        &RecordingResolver::default(),
        ResourceLimits::default(),
    )
    .await
    .unwrap();
    let error = prepared.start_local(Dialer::default()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    // Controller was already bound before the HTTP failure and must be released.
    drop(std::net::TcpListener::bind(controller).unwrap());
    drop(occupied);
    for _ in 0..10 {
        let prepared = PreparedCore::prepare(
            yaml.as_bytes(),
            &RecordingResolver::default(),
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let running = prepared.start_local(Dialer::default()).await.unwrap();
        let selections = running
            .proxy_graph
            .selections
            .iter()
            .map(Arc::downgrade)
            .collect::<Vec<_>>();
        let nodes = running
            .proxy_graph
            .nodes
            .iter()
            .map(Arc::downgrade)
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(1), running.stop())
            .await
            .unwrap()
            .unwrap();
        assert!(nodes.iter().all(|node| node.upgrade().is_none()));
        assert!(
            selections
                .iter()
                .all(|selection| selection.upgrade().is_none())
        );
        drop(std::net::TcpListener::bind(http).unwrap());
        drop(std::net::TcpListener::bind(controller).unwrap());
    }
}

#[cfg(feature = "outbound-socks5")]
#[cfg(feature = "inbound-http")]
#[tokio::test]
async fn http_dual_stack_and_controller_conflicts_roll_back_all_listeners() {
    use crate::inbound::listen::{address_family_unavailable, bind_tcp};
    let occupied_v6 = match bind_tcp("[::1]:0".parse().unwrap()) {
        Ok(listener) => listener,
        Err(error) if address_family_unavailable(&error) => return,
        Err(error) => panic!("{error}"),
    };
    let port = occupied_v6.local_addr().unwrap().port();
    let reserved = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    let controller = reserved.local_addr().unwrap();
    let yaml = format!(
        "{}\nexternal-controller: {controller}\nsecret: fixture-token\n",
        grouped_config("root, DIRECT")
            .replacen("mixed-port: 18080", &format!("mixed-port: {port}"), 1)
            .replace("ipv6: false", "ipv6: true")
    );
    // Controller conflict fails before any business listener can begin serving.
    let prepared = PreparedCore::prepare(
        yaml.as_bytes(),
        &RecordingResolver::default(),
        ResourceLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        prepared
            .start_local(Dialer::default())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    drop(bind_tcp(SocketAddr::from(([127, 0, 0, 1], port))).unwrap());
    drop(reserved);
    // With the Controller free, the second address-family bind fails and must
    // release both the already-bound Controller and IPv4 business listener.
    let prepared = PreparedCore::prepare(
        yaml.as_bytes(),
        &RecordingResolver::default(),
        ResourceLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        prepared
            .start_local(Dialer::default())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    drop(bind_tcp(controller).unwrap());
    drop(bind_tcp(SocketAddr::from(([127, 0, 0, 1], port))).unwrap());
    drop(occupied_v6);
    for _ in 0..3 {
        let prepared = PreparedCore::prepare(
            yaml.as_bytes(),
            &RecordingResolver::default(),
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let running = prepared.start_local(Dialer::default()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), running.stop())
            .await
            .unwrap()
            .unwrap();
        drop(bind_tcp(controller).unwrap());
        drop(bind_tcp(SocketAddr::from(([127, 0, 0, 1], port))).unwrap());
        drop(bind_tcp(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))).unwrap());
    }
}

#[cfg(feature = "outbound-socks5")]
mod wire {
    use super::*;
    use crate::{
        dispatch::{BoxStream, DispatchError},
        session::{Destination, InboundKind, StreamSession},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct SocksFixture {
        address: SocketAddr,
        hits: Arc<AtomicUsize>,
        cancellation: CancellationToken,
        task: Option<JoinHandle<()>>,
    }

    impl SocksFixture {
        async fn start(marker: u8) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let cancellation = CancellationToken::new();
            let stop = cancellation.clone();
            let count = hits.clone();
            let task = tokio::spawn(async move {
                let mut clients = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => break,
                        Some(result) = clients.join_next(), if !clients.is_empty() => { result.unwrap(); }
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            count.fetch_add(1, Ordering::Relaxed);
                            let stop = stop.clone();
                            clients.spawn(async move {
                                tokio::select! {
                                    () = stop.cancelled() => {}
                                    result = serve(stream, marker) => {
                                        if let Err(error) = result {
                                            assert!(matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof), "{error}");
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
                while let Some(result) = clients.join_next().await {
                    result.unwrap();
                }
            });
            Self {
                address,
                hits,
                cancellation,
                task: Some(task),
            }
        }

        async fn stop(mut self) {
            self.cancellation.cancel();
            tokio::time::timeout(Duration::from_secs(1), self.task.take().unwrap())
                .await
                .unwrap()
                .unwrap();
        }
    }

    impl Drop for SocksFixture {
        fn drop(&mut self) {
            self.cancellation.cancel();
        }
    }

    async fn serve(mut stream: tokio::net::TcpStream, marker: u8) -> io::Result<()> {
        let mut head = [0; 3];
        stream.read_exact(&mut head).await?;
        assert_eq!(head, [5, 1, 0]);
        stream.write_all(&[5, 0]).await?;
        stream.read_exact(&mut head).await?;
        assert_eq!(head, [5, 1, 0]);
        let target = crate::socks5::read_destination(&mut stream, false).await?;
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 1, 1]).await?;
        match target {
            Destination::Ip(address) => {
                assert!(address.ip().is_loopback());
                let mut upstream = tokio::net::TcpStream::connect(address).await?;
                tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
            }
            Destination::Domain { .. } => {
                stream.write_all(&[marker; 2]).await?;
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write).await?;
            }
        }
        Ok(())
    }

    fn session(host: &str) -> StreamSession {
        StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Http,
            source: "127.0.0.1:18081".parse().unwrap(),
            destination: Destination::domain(host, 443).unwrap(),
            sniffed_domain: None,
        }
    }

    async fn connect(parts: &BuiltRuntimeParts, host: &str) -> BoxStream {
        tokio::time::timeout(
            Duration::from_secs(1),
            parts.dispatcher.connect_tcp(session(host)),
        )
        .await
        .unwrap()
        .unwrap()
    }

    #[tokio::test]
    async fn controller_selection_is_shared_by_routes_and_upstreams_and_does_not_migrate_streams() {
        let child = SocksFixture::start(b'C').await;
        let first = SocksFixture::start(b'A').await;
        let second = SocksFixture::start(b'B').await;
        let yaml = format!(
            r#"mixed-port: 18080
authentication: [u:p]
proxies:
  - {{name: child, type: socks5, server: 127.0.0.1, port: {}, udp: true, dialer-proxy: path}}
  - {{name: first, type: socks5, server: 127.0.0.1, port: {}}}
  - {{name: second, type: socks5, server: 127.0.0.1, port: {}}}
proxy-groups:
  - {{name: path, type: select, proxies: [first, second, DIRECT, REJECT]}}
rules:
  - DOMAIN,routed.invalid,path
  - MATCH,child
"#,
            child.address.port(),
            first.address.port(),
            second.address.port()
        );
        let prepared =
            PreparedCore::prepare(yaml.as_bytes(), &SystemResolver, ResourceLimits::default())
                .await
                .unwrap();
        let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
        let mut old = connect(&parts, "business.invalid").await;
        assert_eq!(old.read_u8().await.unwrap(), b'C');
        assert_eq!(first.hits.load(Ordering::Relaxed), 1);
        parts.proxy_groups.select("path", "second").unwrap();
        let mut new = connect(&parts, "business.invalid").await;
        assert_eq!(new.read_u8().await.unwrap(), b'C');
        assert_eq!(second.hits.load(Ordering::Relaxed), 1);
        let mut routed = connect(&parts, "routed.invalid").await;
        assert_eq!(routed.read_u8().await.unwrap(), b'B');
        assert_eq!(parts.proxy_groups.state("path").unwrap().now, "second");
        assert_eq!(old.read_u8().await.unwrap(), b'C');
        old.write_all(b"old").await.unwrap();
        let mut echoed = [0; 3];
        old.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"old");

        parts.proxy_groups.select("path", "DIRECT").unwrap();
        let mut direct = connect(&parts, "business.invalid").await;
        assert_eq!(direct.read_u8().await.unwrap(), b'C');
        assert_eq!(first.hits.load(Ordering::Relaxed), 1);
        assert_eq!(second.hits.load(Ordering::Relaxed), 2);
        assert_eq!(child.hits.load(Ordering::Relaxed), 3);
        parts.proxy_groups.select("path", "REJECT").unwrap();
        for host in ["business.invalid", "routed.invalid"] {
            assert!(matches!(
                parts.dispatcher.connect_tcp(session(host)).await,
                Err(DispatchError::NotAllowed)
            ));
        }
        drop((old, new, routed, direct));
        parts.proxy_graph.shutdown().await;
        drop(parts);
        child.stop().await;
        first.stop().await;
        second.stop().await;
    }
}
