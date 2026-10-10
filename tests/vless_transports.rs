#![cfg(feature = "outbound-vless")]
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        VlessOutbound,
    },
    session::{Destination, InboundKind, StreamSession},
};
struct Supplied(Mutex<Option<BoxStream>>);
#[async_trait::async_trait]
impl OutboundConnector for Supplied {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: self.0.lock().unwrap().take().unwrap(),
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
fn node(io: BoxStream, extra: serde_json::Value) -> VlessOutbound {
    let mut node = serde_json::json!({"name":"edge","type":"vless","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707"});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let config = Config::parse_yaml(
        &serde_json::to_vec(
            &serde_json::json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]}),
        )
        .unwrap(),
    )
    .unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    VlessOutbound::new_with_path(
        node,
        UpstreamPath::proxy(Arc::new(Supplied(Mutex::new(Some(io))))),
    )
    .unwrap()
}
fn session() -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: Destination::Ip("192.0.2.1:80".parse().unwrap()),
        sniffed_domain: None,
    }
}

#[tokio::test]
async fn http_camouflage_shutdown_releases_both_directions_without_waiting_for_peer_eof() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "http_camouflage_shutdown_releases_both_directions_without_waiting_for_peer_eof",
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let node = node(Box::new(io), serde_json::json!({"network":"http"}));
        let remote = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
            }
            let header = vole::outbound::encode_request_header(
                uuid::Uuid::from_bytes([7; 16]),
                vole::outbound::VlessCommand::Tcp,
                Some(&session().destination),
            )
            .unwrap();
            let mut received = vec![0; header.len()];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, header);
            peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n\0\0hello")
                .await
                .unwrap();
            peer
        });
        let mut io = node
            .connect_stream(session(), &EstablishContext::default())
            .await
            .unwrap()
            .io;
        let mut hello = [0; 5];
        io.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        let mut peer = remote.await.unwrap();
        io.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(
            peer.write_all(b"late").await.is_err(),
            "HTTP close retained the read direction"
        );
        assert!(!matches!(io.read(&mut [0;1]).await, Ok(n) if n>0));
        drop(io);
        node.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grpc_server_first_flushes_vless_request_without_an_application_write() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "grpc_server_first_flushes_vless_request_without_an_application_write",
    );
    let (io, peer) = tokio::io::duplex(4096);
    let node = node(
        Box::new(io),
        serde_json::json!({"network":"grpc","grpc-opts":{"grpc-service-name":"service"}}),
    );
    let tasks = tokio_util::task::TaskTracker::new();
    let sessions = tasks.clone();
    tasks.spawn(async move {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            sessions.spawn(async move {
                let mut receive = request.into_body();
                let Some(Ok(data)) = receive.data().await else {
                    return;
                };
                assert!(!data.is_empty());
                let mut send = respond
                    .send_response(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                send.send_data(
                    bytes::Bytes::from_static(b"\0\0\0\0\x09\x0a\x07\0\0hello"),
                    false,
                )
                .unwrap();
                let _ = receive.data().await;
            });
        }
    });
    let result = async {
        let mut stream = node
            .connect_stream(
                session(),
                &EstablishContext::with_timeout(Duration::from_millis(100)),
            )
            .await
            .unwrap()
            .io;
        let mut answer = [0; 5];
        let result = stream.read_exact(&mut answer).await;
        (result, answer)
    }
    .await;
    node.shutdown().await;
    tasks.close();
    tasks.wait().await;
    result
        .0
        .expect("VLESS request was not flushed before waiting for the response");
    assert_eq!(&result.1, b"hello");
}
#[tokio::test]
async fn http_upgrade_consumes_early_prefix_and_requires_valid_101_even_fast_open() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "http_upgrade_consumes_early_prefix_and_requires_valid_101_even_fast_open",
    );
    use base64::Engine as _;
    for fast in [false, true] {
        for accept in [false, true] {
            let (io, mut peer) = tokio::io::duplex(4096);
            let node = node(
                Box::new(io),
                serde_json::json!({"network":"ws","ws-opts":{"path":"/upgrade","headers":{"Host":"cover.invalid:443"},"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":fast,"max-early-data":1}}),
            );
            let remote = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(peer.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                assert!(head.starts_with("get /upgrade http/1.1\r\n"));
                assert!(head.contains("host: cover.invalid:443\r\n"));
                assert!(!head.contains("sec-websocket-key"));
                let encoded = head
                    .lines()
                    .find_map(|line| line.strip_prefix("sec-websocket-protocol: "))
                    .unwrap();
                assert_eq!(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(encoded.to_ascii_uppercase())
                        .unwrap(),
                    [0]
                );
                let expected = vole::outbound::encode_request_header(
                    uuid::Uuid::from_bytes([7; 16]),
                    vole::outbound::VlessCommand::Tcp,
                    Some(&session().destination),
                )
                .unwrap();
                let mut rest = vec![0; expected.len() - 1];
                if fast {
                    peer.read_exact(&mut rest).await.unwrap();
                    assert_eq!(rest, &expected[1..]);
                }
                let status = if accept {
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\0\0answer".as_slice()
                } else {
                    b"HTTP/1.1 403 Forbidden\r\n\r\n".as_slice()
                };
                peer.write_all(status).await.unwrap();
                if accept {
                    if !fast {
                        peer.read_exact(&mut rest).await.unwrap();
                        assert_eq!(rest, &expected[1..]);
                    }
                    let mut data = [0; 4];
                    peer.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"body");
                } else {
                    let mut tail = Vec::new();
                    peer.read_to_end(&mut tail).await.unwrap();
                }
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                let result = node
                    .connect_stream(session(), &EstablishContext::default())
                    .await;
                if accept {
                    let mut stream = result.unwrap().io;
                    stream.write_all(b"body").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut answer = [0; 6];
                    stream.read_exact(&mut answer).await.unwrap();
                    assert_eq!(&answer, b"answer");
                } else {
                    assert!(result.is_err(), "failed upgrade reported success");
                }
                remote.await.unwrap();
                node.shutdown().await;
            })
            .await
            .unwrap();
        }
    }
}
