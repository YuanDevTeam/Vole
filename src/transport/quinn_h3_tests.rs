//! Real QUIC/H3 cancellation regressions over bounded in-memory datagrams.
use super::*;
use crate::transport::quic::OwnedRuntime;
use bytes::Buf;
use futures_util::{FutureExt, future::poll_fn};
use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    panic::{AssertUnwindSafe, resume_unwind},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;

const LIMIT: Duration = Duration::from_secs(5);
type Server = h3::server::Connection<h3_quinn::Connection, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Debug)]
struct Socket {
    send: mpsc::Sender<Bytes>,
    receive: Mutex<mpsc::Receiver<Bytes>>,
    local: SocketAddr,
    peer: SocketAddr,
}

#[derive(Debug)]
struct Writable(Mutex<tokio_util::sync::PollSender<Bytes>>);

impl quinn::UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.0.lock().unwrap();
        match ready!(send.poll_reserve(cx)) {
            Ok(()) => {
                send.abort_send();
                Poll::Ready(Ok(()))
            }
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}

impl quinn::AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(Writable(Mutex::new(tokio_util::sync::PollSender::new(
            self.send.clone(),
        ))))
    }

    fn try_send(&self, packet: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        assert_eq!(packet.destination, self.peer);
        assert!(packet.segment_size.is_none());
        self.send
            .try_send(Bytes::copy_from_slice(packet.contents))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(packet) = ready!(self.receive.lock().unwrap().poll_recv(cx)) else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        assert!(packet.len() <= buffers[0].len());
        buffers[0][..packet.len()].copy_from_slice(&packet);
        metadata[0] = quinn::udp::RecvMeta {
            addr: self.peer,
            len: packet.len(),
            stride: packet.len(),
            ecn: None,
            dst_ip: Some(self.local.ip()),
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

struct Pair {
    client: quinn::Connection,
    server: quinn::Connection,
    client_endpoint: quinn::Endpoint,
    server_endpoint: quinn::Endpoint,
    client_runtime: Arc<OwnedRuntime>,
    server_runtime: Arc<OwnedRuntime>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Pair {
    async fn new(server_stream_credit: u32) -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    identity.signing_key.serialize_der().into(),
                ),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        client_config.transport_config(Arc::new(transport(64 * 1024)));
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        server_config.transport_config(Arc::new(transport(server_stream_credit)));
        let client_address: SocketAddr = "192.0.2.1:44001".parse().unwrap();
        let server_address: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let (to_client, from_server) = mpsc::channel(32);
        let (to_server, from_client) = mpsc::channel(32);
        let client_runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
        let server_runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
        let mut client_endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(Socket {
                send: to_server,
                receive: Mutex::new(from_server),
                local: client_address,
                peer: server_address,
            }),
            client_runtime.clone(),
        )
        .unwrap();
        client_endpoint.set_default_client_config(client_config);
        let server_endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(Socket {
                send: to_client,
                receive: Mutex::new(from_client),
                local: server_address,
                peer: client_address,
            }),
            server_runtime.clone(),
        )
        .unwrap();
        let (client, server) = timeout(LIMIT, async {
            tokio::join!(
                client_endpoint
                    .connect(server_address, "localhost")
                    .unwrap(),
                async { server_endpoint.accept().await.unwrap().await }
            )
        })
        .await
        .unwrap();
        let client = client.unwrap();
        let server = server.unwrap();
        let handshake = client
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
        Self {
            client,
            server,
            client_endpoint,
            server_endpoint,
            client_runtime,
            server_runtime,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
        }
    }

    fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        let cancel = self.cancel.clone();
        self.tasks.push(tokio::spawn(async move {
            tokio::select! { biased; () = cancel.cancelled() => {}, () = future => {} }
        }));
    }

    async fn h3(&mut self) -> (Client, Server) {
        let (client, mut control) = attach(self.client.clone(), 16 * 1024).await.unwrap();
        let keep_client = client.clone();
        self.spawn(async move {
            let _keep_client = keep_client;
            let _ = control.wait_idle().await;
        });
        let server = h3::server::builder()
            .max_field_section_size(16 * 1024)
            .build::<_, Bytes>(h3_quinn::Connection::new(self.server.clone()))
            .await
            .unwrap();
        (client, server)
    }

    async fn stop(mut self) {
        self.client_endpoint.close(0_u8.into(), b"");
        self.server_endpoint.close(0_u8.into(), b"");
        self.cancel.cancel();
        let mut failed_task = None;
        for task in self.tasks.drain(..) {
            if let Err(error) = task.await {
                failed_task.get_or_insert(error);
            }
        }
        let _ = timeout(LIMIT, async {
            tokio::join!(
                self.client_endpoint.wait_idle(),
                self.server_endpoint.wait_idle()
            )
        })
        .await;
        self.client_runtime.stop().await;
        self.server_runtime.stop().await;
        if let Some(error) = failed_task {
            resume_unwind(error.into_panic());
        }
    }
}

fn transport(stream_credit: u32) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(None)
        .max_concurrent_bidi_streams(8_u8.into())
        .max_concurrent_uni_streams(8_u8.into())
        .stream_receive_window(stream_credit.into())
        .receive_window((128_u32 * 1024).into())
        .send_window(64 * 1024)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    config
}

async fn settle(pair: Pair, future: impl Future<Output = ()>) {
    let result = AssertUnwindSafe(timeout(LIMIT, future))
        .catch_unwind()
        .await;
    pair.stop().await;
    match result {
        Ok(result) => result.expect("bounded memory H3 operation timed out"),
        Err(panic) => resume_unwind(panic),
    }
}

#[path = "quinn_h3_cancel_tests.rs"]
mod cancellation;
