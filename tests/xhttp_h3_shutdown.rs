#![cfg(feature = "outbound-vless")]
//! Memory-only QUIC regression through the public VLESS/XHTTP connector.
#[path = "support/memory_quic.rs"]
mod memory_quic;

use bytes::{Buf, Bytes};
use memory_quic::{MemoryPackets, MemoryUpstream, PeerSocket};
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::mpsc,
    task::JoinSet,
};
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        VlessOutbound,
    },
    session::{Datagram, Destination, InboundKind, StreamSession},
};

#[derive(Debug)]
struct PeerRuntime {
    tasks: Mutex<Option<JoinSet<()>>>,
}

impl PeerRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tasks: Mutex::new(Some(JoinSet::new())),
        })
    }

    async fn stop(&self) {
        // Close task admission before aborting, so a retiring driver cannot
        // leave new background work outside this join barrier.
        let Some(mut tasks) = self.tasks.lock().unwrap().take() else {
            return;
        };
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                assert!(
                    error.is_cancelled(),
                    "memory QUIC peer task failed: {error}"
                );
            }
        }
    }
}

impl quinn::Runtime for PeerRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, instant)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if let Some(tasks) = self.tasks.lock().unwrap().as_mut() {
            tasks.spawn(future);
        }
    }

    fn wrap_udp_socket(
        &self,
        _: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

struct SlowPackets {
    inner: MemoryPackets,
    state: Arc<AtomicU8>,
    handshake_delay: Option<Duration>,
    delayed_receive: Option<(Datagram, Pin<Box<tokio::time::Sleep>>)>,
}
#[async_trait::async_trait]
impl DatagramTransport for SlowPackets {
    fn payload_budget(&self, target: &Destination) -> DatagramBudget {
        self.inner.payload_budget(target)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        match self.state.load(Ordering::SeqCst) {
            1 => tokio::time::sleep(Duration::from_millis(20)).await,
            2 => std::future::pending().await,
            _ => {}
        }
        self.inner.send(packet).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.delayed_receive.is_none() {
            let packet = self.inner.receive().await?;
            let Some(delay) = self.handshake_delay.take() else {
                return Ok(packet);
            };
            // Keep the packet and timer across cancelled receive futures.
            self.delayed_receive = Some((packet, Box::pin(tokio::time::sleep(delay))));
        }
        self.delayed_receive.as_mut().unwrap().1.as_mut().await;
        Ok(self.delayed_receive.take().unwrap().0)
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.inner.close().await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Closing {
    Normal,
    Deadline,
    Stop,
}

struct MixedUpstream {
    datagram: Mutex<Option<SlowPackets>>,
    stream: Mutex<Option<DuplexStream>>,
}
#[async_trait::async_trait]
impl OutboundConnector for MixedUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: Box::new(self.stream.lock().unwrap().take().unwrap()),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(self.datagram.lock().unwrap().take().unwrap()))
    }
}

#[tokio::test]
async fn h3_shutdown_does_not_cancel_the_last_upload() {
    for mode in ["stream-one", "stream-up"] {
        exercise(mode, Closing::Normal, None).await;
    }
}

#[tokio::test]
async fn h3_shutdown_cleanup_joins_peer_after_a_delayed_handshake() {
    for mode in ["stream-one", "stream-up"] {
        // Inflate the peer's RTT/PTO before uploading. Its normal QUIC close
        // retention can then exceed the fixture's two-second cleanup budget.
        exercise(mode, Closing::Normal, Some(Duration::from_millis(500))).await;
    }
}

#[tokio::test]
async fn h3_stalled_upload_is_bounded_and_owner_stop_joins_it() {
    for closing in [Closing::Deadline, Closing::Stop] {
        exercise("stream-one", closing, None).await;
    }
}

#[tokio::test]
async fn h3_first_upload_precedes_responses_and_mixed_download_cancel_joins_owners() {
    tokio::time::timeout(
        Duration::from_secs(6),
        run("stream-up", Closing::Stop, None, true),
    )
    .await
    .expect("mixed H3/H2 owners did not join");
}

async fn exercise(mode: &str, closing: Closing, handshake_delay: Option<Duration>) {
    tokio::time::timeout(
        Duration::from_secs(6),
        run(mode, closing, handshake_delay, false),
    )
    .await
    .expect("memory QUIC fixture exceeded its cleanup bound");
}

async fn run(
    mode: &str,
    closing: Closing,
    handshake_delay: Option<Duration>,
    mixed_first_bytes: bool,
) {
    let server_address: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let client_address: SocketAddr = "192.0.2.2:1234".parse().unwrap();
    let (to_server, from_client) = mpsc::channel(32);
    let (to_client, from_server) = mpsc::channel(32);
    let client_io = MemoryPackets {
        send: to_server,
        receive: from_server,
        remote: server_address,
    };
    let socket = Arc::new(PeerSocket {
        send: to_client,
        receive: Mutex::new(from_client),
        local: server_address,
        remote: client_address,
    });
    let certificate = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .mtu_discovery_config(None);
    let peer_runtime = PeerRuntime::new();
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        peer_runtime.clone(),
    )
    .unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (cleanup, cleaned) = tokio::sync::oneshot::channel();
    let (uploaded, first_upload) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let mut downloads = Vec::new();
        let mut request = loop {
            let (headers, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            if !mixed_first_bytes {
                stream.send_response(http::Response::new(())).await.unwrap();
            }
            if headers.method() == http::Method::POST {
                break stream;
            }
            assert_eq!(headers.method(), http::Method::GET);
            downloads.push(stream); // Never send a download tail or EOF.
        };
        started.send(()).unwrap();
        let mut received = Vec::new();
        let mut uploaded = Some(uploaded);
        while let Ok(Ok(Some(mut data))) =
            tokio::time::timeout(Duration::from_secs(1), request.recv_data()).await
        {
            received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            if received.ends_with(&[b'x'; 16384])
                && let Some(uploaded) = uploaded.take()
            {
                let _ = uploaded.send(());
            }
        }
        let _ = cleaned.await;
        if mixed_first_bytes || closing == Closing::Normal && handshake_delay.is_none() {
            let closed = tokio::time::timeout(Duration::from_secs(2), connection.closed())
                .await
                .expect("quiet client retirement never sent CONNECTION_CLOSE");
            let quinn::ConnectionError::ApplicationClosed(error) = closed else {
                panic!("quiet retirement failed its close exchange: {closed}");
            };
            assert!(
                error.error_code == 0_u8.into()
                    || error.error_code.into_inner() == h3::error::Code::H3_NO_ERROR.value()
            );
        }
        drop(h3);
        endpoint.close(0_u32.into(), b"");
        received
    });
    let mut config = serde_json::json!({
        "mixed-port":1080,
        "proxies":[{
            "name":"peer", "type":"vless", "server":"192.0.2.1", "port":443,
            "uuid":"07070707-0707-0707-0707-070707070707",
            "tls":true, "skip-cert-verify":true, "servername":"fixture.invalid",
            "alpn":["h3"], "network":"xhttp", "xhttp-opts":{"mode":mode}
        }],
        "rules":["MATCH,peer"]
    });
    let (h2_client, h2_peer, h2_ready) = if mixed_first_bytes {
        config["proxies"][0]["xhttp-opts"]["download-settings"] = serde_json::json!({
            "port":8443, "tls":false, "skip-cert-verify":false, "alpn":["h2"]
        });
        let (client, server) = tokio::io::duplex(4096);
        let (seen, ready) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::GET);
            let _held = (request, response); // Keep HEADERS pending until client cancellation.
            seen.send(()).unwrap();
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
                panic!("unexpected second download request");
            }
        });
        (Some(client), Some(peer), Some(ready))
    } else {
        (None, None, None)
    };
    let config = Config::parse_yaml(config.to_string().as_bytes()).unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        panic!("protocol")
    };
    let state = Arc::new(AtomicU8::new(0));
    let packets = SlowPackets {
        inner: client_io,
        state: state.clone(),
        handshake_delay,
        delayed_receive: None,
    };
    let upstream: Arc<dyn OutboundConnector> = if let Some(stream) = h2_client {
        Arc::new(MixedUpstream {
            datagram: Mutex::new(Some(packets)),
            stream: Mutex::new(Some(stream)),
        })
    } else {
        Arc::new(MemoryUpstream(Mutex::new(Some(packets))))
    };
    let outbound = VlessOutbound::new_with_path(config, UpstreamPath::proxy(upstream)).unwrap();
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: client_address,
        destination: Destination::domain("target.invalid", 443).unwrap(),
        sniffed_domain: None,
    };
    let mut stream = outbound
        .connect_stream(session, &EstablishContext::default())
        .await
        .unwrap()
        .io;
    ready.await.unwrap();
    if let Some(ready) = h2_ready {
        ready.await.unwrap();
    }
    state.store(
        if mixed_first_bytes {
            0
        } else if closing == Closing::Normal {
            1
        } else {
            2
        },
        Ordering::SeqCst,
    );
    stream.write_all(&[b'x'; 16384]).await.unwrap();
    if closing == Closing::Normal || mixed_first_bytes {
        stream.flush().await.unwrap();
    }
    if mixed_first_bytes {
        tokio::time::timeout(Duration::from_secs(1), first_upload)
            .await
            .expect("upload waited for an HTTP response")
            .unwrap();
        let mut bytes = [0; 1];
        let mut output = ReadBuf::new(&mut bytes);
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_read(cx, &mut output)))
                .await
                .is_pending(),
            "download unexpectedly received response HEADERS"
        );
    }
    // A stalled controlled transport can exhaust native QUIC send capacity.
    // Shutdown must bound this outstanding flush instead of the fixture
    // waiting indefinitely for flush before it even requests shutdown.
    assert!(
        poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_shutdown(cx)))
            .await
            .is_pending()
    );
    if closing == Closing::Stop {
        outbound.shutdown().await;
    }
    let result = tokio::time::timeout(Duration::from_millis(1200), stream.shutdown())
        .await
        .expect("upload completion prevented bounded close");
    if closing != Closing::Stop {
        result.unwrap();
    }
    if closing != Closing::Stop {
        stream.shutdown().await.unwrap();
    }
    let _ = cleanup.send(());
    let received = reader.await.unwrap();
    outbound.shutdown().await;
    if let Some(peer) = h2_peer {
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .expect("mixed H2 peer did not join")
            .unwrap();
    }
    // QUIC retains closed connections for 3 * PTO, which depends on RTT and
    // can legitimately exceed two seconds. After the upload and client Stop,
    // reclaim the fixture's tasks explicitly instead of timing its draining.
    tokio::time::timeout(Duration::from_secs(2), peer_runtime.stop())
        .await
        .expect("memory QUIC peer tasks did not join");
    if closing == Closing::Normal || mixed_first_bytes {
        assert!(
            received.ends_with(&[b'x'; 16384]),
            "mode={mode}: only {} upload bytes reached the peer",
            received.len()
        );
    }
}
