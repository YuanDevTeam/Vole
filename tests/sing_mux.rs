#![cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, SingMuxConnector,
        VlessOutbound,
    },
    session::{Destination, InboundKind, StreamSession},
};

struct MemoryPeer {
    count: AtomicUsize,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    udp: bool,
    protocol: u8,
}
#[async_trait]
impl OutboundConnector for MemoryPeer {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        let (client, mut server) = tokio::io::duplex(65536);
        let udp = self.udp;
        let protocol = self.protocol;
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let mut header = [0; 23];
            server.read_exact(&mut header).await.unwrap();
            assert_eq!(
                header[18], 1,
                "sing-mux is a normal VLESS TCP destination, not XUDP"
            );
            assert_eq!(&header[19..23], &[1, 188, 2, 20]);
            let mut target = [0; 20];
            server.read_exact(&mut target).await.unwrap();
            assert_eq!(&target, b"sp.mux.sing-box.arpa");
            let mut mux = [0; 2];
            server.read_exact(&mut mux).await.unwrap();
            assert_eq!(mux, [0, protocol]);
            server.write_all(&[0, 0]).await.unwrap();
            if protocol == 0 {
                let mut opened = std::collections::HashSet::new();
                loop {
                    let mut head = [0; 8];
                    if server.read_exact(&mut head).await.is_err() {
                        break;
                    }
                    assert_eq!(head[0], 1);
                    let len = u16::from_le_bytes(head[2..4].try_into().unwrap()) as usize;
                    let id = u32::from_le_bytes(head[4..].try_into().unwrap());
                    assert!(id >= 3 && id % 2 == 1);
                    let mut data = vec![0; len];
                    server.read_exact(&mut data).await.unwrap();
                    match head[1] {
                        0 => {
                            assert_eq!(len, 0);
                        }
                        1 => {
                            assert_eq!(len, 0);
                            server.write_all(&head).await.unwrap();
                        }
                        2 => {
                            if opened.insert(id) {
                                assert_eq!(data, [0, 0, 1, 192, 0, 2, 1, 1, 187]);
                                data = b"\x00hello".to_vec();
                            }
                            head[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
                            server.write_all(&head).await.unwrap();
                            server.write_all(&data).await.unwrap();
                        }
                        _ => panic!("unexpected smux control frame"),
                    }
                    server.flush().await.unwrap();
                }
                return;
            }
            if protocol == 1 {
                use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
                let mut connection = yamux::Connection::new(
                    server.compat(),
                    yamux::Config::default(),
                    yamux::Mode::Server,
                );
                let mut tasks = tokio::task::JoinSet::new();
                while let Some(Ok(stream)) =
                    futures_util::future::poll_fn(|cx| connection.poll_next_inbound(cx)).await
                {
                    tasks.spawn(async move {
                        let mut io = stream.compat();
                        let mut request = [0; 9];
                        io.read_exact(&mut request).await.unwrap();
                        assert_eq!(request, [0, 0, 1, 192, 0, 2, 1, 1, 187]);
                        io.write_all(b"\x00hello").await.unwrap();
                        io.flush().await.unwrap();
                        let mut scratch = [0; 1024];
                        while let Ok(n) = io.read(&mut scratch).await {
                            if n == 0 {
                                let _ = io.write_all(b"tail").await;
                                let _ = io.shutdown().await;
                                break;
                            }
                            io.write_all(&scratch[..n]).await.unwrap();
                            io.flush().await.unwrap();
                        }
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                return;
            }
            let mut connection = h2::server::handshake(server).await.unwrap();
            let mut streams = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut response))) = connection.accept().await {
                assert_eq!(request.method(), "CONNECT");
                streams.spawn(async move {
                    let mut input = request.into_body();
                    let first = input.data().await.unwrap().unwrap();
                    if udp {
                        assert_eq!(&first[..2], &[0, 3]);
                    } else {
                        assert_eq!(first.as_ref(), &[0, 0, 1, 192, 0, 2, 1, 1, 187]);
                    }
                    input.flow_control().release_capacity(first.len()).unwrap();
                    let mut output = response
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    output
                        .send_data(
                            Bytes::from_static(if udp { b"\x00" } else { b"\x00hello" }),
                            false,
                        )
                        .unwrap();
                    loop {
                        match input.data().await {
                            Some(Ok(data)) => {
                                input.flow_control().release_capacity(data.len()).unwrap();
                                if output.send_data(data, false).is_err() {
                                    break;
                                }
                            }
                            None => {
                                let _ = output.send_data(Bytes::from_static(b"tail"), true);
                                break;
                            }
                            Some(Err(_)) => break,
                        }
                    }
                });
            }
            while let Some(result) = streams.join_next().await {
                result.unwrap();
            }
        }));
        Ok(ConnectedStream {
            io: Box::new(client),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn outbound(peer: Arc<MemoryPeer>, options: &str) -> SingMuxConnector {
    let raw = format!(
        "mixed-port: 1080\nproxies:\n- name: edge\n  type: vless\n  server: example.com\n  port: 443\n  uuid: 07070707-0707-0707-0707-070707070707\n  smux: {{enabled: true, {options}}}\nrules: [MATCH,edge]\n"
    );
    let raw = raw.replace("rules: [MATCH,edge]", "rules: ['MATCH,edge']");
    let config = Config::parse_yaml(raw.as_bytes()).unwrap();
    let options = config.proxies[0].smux.clone().unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    SingMuxConnector::new(
        Arc::new(VlessOutbound::new_with_upstream(config, peer).unwrap()),
        options,
    )
}
async fn open(node: &SingMuxConnector) -> BoxStream {
    node.connect_stream(
        StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::InternalMeasure,
            source: "127.0.0.1:1".parse().unwrap(),
            destination: Destination::Ip("192.0.2.1:443".parse().unwrap()),
            sniffed_domain: None,
        },
        &EstablishContext::default(),
    )
    .await
    .unwrap()
    .io
}
async fn hello(io: &mut BoxStream) {
    let mut greeting = [0; 5];
    io.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
}
#[tokio::test]
async fn shared_mux_preserves_h2mux_yamux_tail_and_smux_whole_close() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for (protocol, wire) in [("h2mux", 2), ("yamux", 1), ("smux", 0)] {
            let peer = Arc::new(MemoryPeer {
                count: AtomicUsize::new(0),
                tasks: Mutex::new(vec![]),
                udp: false,
                protocol: wire,
            });
            let node = outbound(
                peer.clone(),
                &format!("protocol: {protocol}, max-connections: 1"),
            );
            let mut first = open(&node).await;
            let mut sibling = open(&node).await;
            hello(&mut first).await;
            hello(&mut sibling).await;
            assert_eq!(peer.count.load(Ordering::SeqCst), 1);
            first.write_all(b"upload").await.unwrap();
            first.shutdown().await.unwrap();
            first.shutdown().await.unwrap();
            assert!(first.write_all(b"closed").await.is_err());
            let mut tail = Vec::new();
            first.read_to_end(&mut tail).await.unwrap();
            assert_eq!(
                tail,
                if protocol == "smux" {
                    &b""[..]
                } else {
                    &b"uploadtail"[..]
                },
                "{protocol}"
            );
            sibling.write_all(b"alive").await.unwrap();
            sibling.flush().await.unwrap();
            let mut response = [0; 5];
            sibling.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"alive");
            node.shutdown().await;
            drop((first, sibling));
            let tasks = std::mem::take(&mut *peer.tasks.lock().unwrap());
            for task in tasks {
                task.await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn yamux_replacing_dropped_streams_at_capacity_keeps_the_sibling_alive() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "yamux_replacing_dropped_streams_at_capacity_keeps_the_sibling_alive",
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        let peer = Arc::new(MemoryPeer {
            count: AtomicUsize::new(0),
            tasks: Mutex::new(vec![]),
            udp: false,
            protocol: 1,
        });
        let node = outbound(peer.clone(), "protocol: yamux, max-connections: 1");
        let mut streams = Vec::new();
        for _ in 0..64 {
            let mut stream = open(&node).await;
            hello(&mut stream).await;
            streams.push(stream);
        }
        let mut sibling = streams.pop().unwrap();
        drop(streams);
        let mut replacement = open(&node).await;
        hello(&mut replacement).await;
        sibling.write_all(b"live").await.unwrap();
        sibling.flush().await.unwrap();
        let mut response = [0; 4];
        sibling.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"live");
        drop((sibling, replacement));
        node.shutdown().await;
        let tasks = std::mem::take(&mut *peer.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sing_mux_scheduling_uses_the_selected_branch_not_a_global_stream_quota() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "sing_mux_scheduling_uses_the_selected_branch_not_a_global_stream_quota",
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        for (protocol, wire) in [("h2mux", 2), ("smux", 0), ("yamux", 1)] {
            for (settings, counts) in [
                ("min-streams: 8", [1, 2, 3, 4]),
                ("max-connections: 1", [1, 1, 1, 1]),
                ("max-connections: 2, min-streams: 2", [1, 1, 2, 2]),
                ("max-streams: 2", [1, 1, 2, 2]),
            ] {
                let peer = Arc::new(MemoryPeer {
                    count: AtomicUsize::new(0),
                    tasks: Mutex::new(vec![]),
                    udp: false,
                    protocol: wire,
                });
                let node = outbound(peer.clone(), &format!("protocol: {protocol}, {settings}"));
                let mut streams = Vec::new();
                for count in counts {
                    let mut stream = open(&node).await;
                    hello(&mut stream).await;
                    assert_eq!(
                        peer.count.load(Ordering::SeqCst),
                        count,
                        "{protocol}, {settings}"
                    );
                    streams.push(stream);
                }
                for mut stream in streams {
                    stream.write_all(b"still alive").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut response = [0; 11];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"still alive");
                    stream.shutdown().await.unwrap();
                }
                node.shutdown().await;
                let tasks = std::mem::take(&mut *peer.tasks.lock().unwrap());
                for task in tasks {
                    task.await.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
}

struct CapturePeer(Mutex<Option<tokio::io::DuplexStream>>);
#[async_trait]
impl OutboundConnector for CapturePeer {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: Box::new(self.0.lock().unwrap().take().unwrap()),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test]
async fn h2mux_sends_idle_ping_and_retires_a_peer_that_never_acknowledges() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "h2mux_sends_idle_ping_and_retires_a_peer_that_never_acknowledges",
    );
    let raw = serde_json::json!({"mixed-port":1080,"proxies":[{"name":"edge","type":"vless","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707","smux":{"enabled":true,"max-connections":1}}],"rules":["MATCH,edge"]});
    let config = Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
    let options = config.proxies[0].smux.clone().unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let (io, mut peer) = tokio::io::duplex(4096);
    let node = SingMuxConnector::new(
        Arc::new(
            VlessOutbound::new_with_upstream(config, Arc::new(CapturePeer(Mutex::new(Some(io)))))
                .unwrap(),
        ),
        options,
    );
    let (ping, mut received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut preface = [0; 45];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface[43..], &[0, 2]);
        peer.write_all(b"\0\0\0\0\0\x04\0\0\0\0\0").await.unwrap();
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let mut ping = Some(ping);
        loop {
            let mut header = [0; 9];
            if peer.read_exact(&mut header).await.is_err() {
                break;
            }
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            assert!(length <= 16384);
            let mut payload = vec![0; length];
            peer.read_exact(&mut payload).await.unwrap();
            if header[3] == 6 && header[4] == 0 {
                assert_eq!(length, 8);
                ping.take().unwrap().send(()).unwrap();
                // Deliberately never ACK. The owned driver must fail closed.
            }
        }
    });
    let held = open(&node).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(29)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        received.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::timeout(Duration::from_secs(1), received)
        .await
        .expect("missing sing-mux idle PING")
        .unwrap();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .expect("unacknowledged PING retained physical IO")
        .unwrap();
    drop(held);
    node.shutdown().await;
}

#[tokio::test]
async fn only_tcp_preserves_all_three_vless_udp_wire_commands() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "only_tcp_preserves_all_three_vless_udp_wire_commands",
    );
    use vole::session::{Datagram, DatagramSession};
    tokio::time::timeout(Duration::from_secs(3), async {
        for protocol in ["h2mux", "smux", "yamux"] {
            for (codec, command) in [("xudp", 3), ("none", 2), ("packetaddr", 2)] {
                let raw = serde_json::json!({"mixed-port":1080,"proxies":[{"name":"edge","type":"vless","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707","udp":true,"packet-encoding":codec,"smux":{"enabled":true,"protocol":protocol,"padding":true,"only-tcp":true}}],"rules":["MATCH,edge"]});
                let config = Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
                let options=config.proxies[0].smux.clone().unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else { unreachable!() };
                let (io, mut peer) = tokio::io::duplex(4096);
                let node = SingMuxConnector::new(Arc::new(VlessOutbound::new_with_upstream(config, Arc::new(CapturePeer(Mutex::new(Some(io))))).unwrap()),options);
                let mut association = node.open_datagram(
                    DatagramRequest::new(DatagramSession::new(InboundKind::InternalMeasure, "127.0.0.1:1".parse().unwrap())),
                    &EstablishContext::default(),
                ).await.unwrap();
                association.send(Datagram { remote: Destination::Ip("192.0.2.1:443".parse().unwrap()), payload: Bytes::from_static(b"udp"), sniffed_domain: None }).await.unwrap();
                let mut header = [0; 19];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(header[18], command, "{protocol} / {codec} must not become sing-mux TCP");
                association.close().await.unwrap();
                drop(association);
                node.shutdown().await;
                let mut body = Vec::new();
                peer.read_to_end(&mut body).await.unwrap();
                assert!(!body.windows(20).any(|part| part == b"sp.mux.sing-box.arpa"));
                assert!(body.windows(3).any(|part| part == b"udp"));
            }
        }
    }).await.unwrap();
}
#[tokio::test]
async fn h2mux_reuses_physical_vless_and_cancels_only_one_logical_stream() -> io::Result<()> {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "h2mux_reuses_physical_vless_and_cancels_only_one_logical_stream",
    );
    siblings("h2mux", 2).await
}
#[tokio::test]
async fn yamux_reuses_physical_vless_and_cancels_only_one_logical_stream() -> io::Result<()> {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "yamux_reuses_physical_vless_and_cancels_only_one_logical_stream",
    );
    siblings("yamux", 1).await
}
#[tokio::test]
async fn smux_reuses_physical_vless_and_cancels_only_one_logical_stream() -> io::Result<()> {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "smux_reuses_physical_vless_and_cancels_only_one_logical_stream",
    );
    siblings("smux", 0).await
}
async fn siblings(protocol: &str, wire: u8) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = Arc::new(MemoryPeer {
            count: AtomicUsize::new(0),
            tasks: Mutex::new(vec![]),
            udp: false,
            protocol: wire,
        });
        let node = outbound(
            peer.clone(),
            &format!("max-connections: 1, protocol: {protocol}"),
        );
        let mut first = open(&node).await;
        hello(&mut first).await;
        let mut second = open(&node).await;
        hello(&mut second).await;
        assert_eq!(peer.count.load(Ordering::SeqCst), 1);
        first.shutdown().await.unwrap();
        drop(first);
        second.write_all(b"sibling alive").await.unwrap();
        second.flush().await.unwrap();
        let mut response = [0; 13];
        second.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"sibling alive");
        drop(second);
        node.shutdown().await;
        let tasks = std::mem::take(&mut *peer.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .map_err(io::Error::other)
}

#[tokio::test]
async fn sing_mux_udp_preserves_addresses_and_cancellation_safe_partial_frames() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "sing_mux_udp_preserves_addresses_and_cancellation_safe_partial_frames",
    );
    use vole::{
        dispatch::DatagramBudget,
        session::{Datagram, DatagramSession},
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = Arc::new(MemoryPeer {
            count: AtomicUsize::new(0),
            tasks: Mutex::new(vec![]),
            udp: true,
            protocol: 2,
        });
        let node = outbound(peer.clone(), "max-connections: 1");
        let mut io = node
            .open_datagram(
                DatagramRequest::new(DatagramSession::new(
                    InboundKind::InternalMeasure,
                    "127.0.0.1:1".parse().unwrap(),
                ))
                .with_budget(DatagramBudget::new(15000, 15000)),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        for remote in [
            "192.0.2.1:1234".parse().map(Destination::Ip).unwrap(),
            "[2001:db8::1]:1234".parse().map(Destination::Ip).unwrap(),
        ] {
            assert!(
                tokio::time::timeout(Duration::from_millis(1), io.receive())
                    .await
                    .is_err()
            );
            let payload = Bytes::from(vec![0x5a; 15000]);
            io.send(Datagram {
                remote: remote.clone(),
                payload: payload.clone(),
                sniffed_domain: None,
            })
            .await
            .unwrap();
            let received = io.receive().await.unwrap();
            assert_eq!(received.remote, remote);
            assert_eq!(received.payload, payload);
        }
        io.close().await.unwrap();
        drop(io);
        node.shutdown().await;
        let tasks = std::mem::take(&mut *peer.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}
