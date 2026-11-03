//! Internal ownership evidence complementing the public mihomo process tests.
use super::*;
use crate::dialer::{SocketProtector, SystemResolver};
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Default)]
struct CountProtect(AtomicUsize);

impl SocketProtector for CountProtect {
    fn protect(&self, _socket: i32) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn login(proxy: SocketAddr) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    stream
}

#[tokio::test]
async fn hundred_active_stops_release_activities_graph_and_protect_owner() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for cycle in 0..100 {
            // Select a jointly free TCP/UDP port before preparing the runtime.
            let (reserved, reserved_udp) = (0..32)
                .find_map(|_| {
                    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    match std::net::UdpSocket::bind(tcp.local_addr().unwrap()) {
                        Ok(udp) => Some((tcp, udp)),
                        Err(error) if error.kind() == io::ErrorKind::AddrInUse => None,
                        Err(error) => panic!("fixture bind: {error}"),
                    }
                })
                .expect("fixture TCP/UDP port pair");
            let proxy = reserved.local_addr().unwrap();
            let yaml = format!(
                r#"
mixed-port: {}
ipv6: false
proxies:
  - {{name: unused, type: socks5, server: 127.0.0.1, port: 9, udp: true}}
proxy-groups:
  - {{name: path, type: select, proxies: [DIRECT, unused]}}
rules: ['MATCH,path']
"#,
                proxy.port()
            );
            let protected = Arc::new(CountProtect::default());
            if cycle % 10 == 0 {
                let prepared = PreparedCore::prepare(
                    yaml.as_bytes(),
                    &SystemResolver,
                    ResourceLimits::default(),
                )
                .await
                .unwrap();
                assert!(
                    prepared
                        .start_local(Dialer::default().with_protector(protected.clone()))
                        .await
                        .is_err()
                );
                assert_eq!(Arc::strong_count(&protected), 1);
                assert_eq!(protected.0.load(Ordering::SeqCst), 0);
            }
            drop((reserved, reserved_udp));
            let prepared =
                PreparedCore::prepare(yaml.as_bytes(), &SystemResolver, ResourceLimits::default())
                    .await
                    .unwrap();
            let BuiltRuntimeParts {
                dispatcher,
                geodata_updater,
                proxy_graph,
                ..
            } = prepared
                .build_dispatcher(Dialer::default().with_protector(protected.clone()))
                .unwrap();
            let nodes = proxy_graph
                .nodes
                .iter()
                .map(Arc::downgrade)
                .collect::<Vec<_>>();
            let selections = proxy_graph
                .selections
                .iter()
                .map(Arc::downgrade)
                .collect::<Vec<_>>();
            let stats = RuntimeResourceStats::new("lifecycle_fixture");
            let dispatcher = observe_sessions_with_stats(
                observe_handshakes_with_stats(dispatcher, stats.clone()),
                stats.clone(),
            );
            let running = RunningCore::start_components(
                &prepared.config.inbounds,
                dispatcher,
                None,
                None,
                None,
                geodata_updater,
                prepared.geodata_registration,
                proxy_graph,
                None,
            )
            .await
            .unwrap();
            let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = origin.local_addr().unwrap();
            let mut client = login(proxy).await;
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&target.port().to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0);
            let (mut remote, _) = origin.accept().await.unwrap();
            client.write_all(b"active").await.unwrap();
            let mut payload = [0; 6];
            remote.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"active");
            remote.write_all(&payload).await.unwrap();
            client.read_exact(&mut payload).await.unwrap();
            let udp_origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut control = login(proxy).await;
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            control.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            let relay = SocketAddr::from((
                [reply[4], reply[5], reply[6], reply[7]],
                u16::from_be_bytes([reply[8], reply[9]]),
            ));
            let mut datagram = vec![0, 0, 0, 1, 127, 0, 0, 1];
            datagram.extend_from_slice(&udp_origin.local_addr().unwrap().port().to_be_bytes());
            datagram.extend_from_slice(b"active");
            udp_client.send_to(&datagram, relay).await.unwrap();
            let mut bytes = [0; 128];
            let (length, peer) = udp_origin.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..length], b"active");
            udp_origin.send_to(&bytes[..length], peer).await.unwrap();
            let (length, _) = udp_client.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..length], datagram);
            let active = stats.snapshot();
            assert_eq!(active.tcp_current, 1);
            assert_eq!(active.udp_current, 1);
            assert_eq!(active.handshake_current, 0);
            assert_eq!(protected.0.load(Ordering::SeqCst), 2);
            tokio::time::timeout(Duration::from_secs(5), running.stop())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(client.read(&mut bytes).await.unwrap(), 0);
            assert_eq!(control.read(&mut bytes).await.unwrap(), 0);
            assert_eq!(remote.read(&mut bytes).await.unwrap(), 0);
            let stopped = stats.snapshot();
            assert_eq!(stopped.tcp_current, 0);
            assert_eq!(stopped.udp_current, 0);
            assert_eq!(stopped.handshake_current, 0);
            assert!(nodes.iter().all(|node| node.upgrade().is_none()));
            assert!(
                selections
                    .iter()
                    .all(|selection| selection.upgrade().is_none())
            );
            assert_eq!(Arc::strong_count(&protected), 1);
            udp_client.send_to(&datagram, relay).await.unwrap();
            tokio::task::yield_now().await;
            assert_eq!(protected.0.load(Ordering::SeqCst), 2);
            drop(std::net::TcpListener::bind(proxy).unwrap());
            drop(std::net::UdpSocket::bind(proxy).unwrap());
        }
    })
    .await
    .expect("100 lifecycle cycles must complete within the fixture deadline");
}
