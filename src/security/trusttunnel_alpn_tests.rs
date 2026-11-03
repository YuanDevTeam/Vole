//! Authenticated TrustTunnel H2 over duplex IO, without host sockets.
use super::*;
use crate::{
    config::{Config, ProxyProtocol},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        trusttunnel::TrustTunnelOutbound,
    },
    session::{Destination, InboundKind, StreamSession},
};
use async_trait::async_trait;
use tokio_util::task::TaskTracker;

struct MemoryUpstream(Mutex<Option<tokio::io::DuplexStream>>);

#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let io = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(DispatchError::NotAllowed)?;
        Ok(ConnectedStream {
            io: Box::new(io),
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

async fn serve_h2(peer: tokio::io::DuplexStream, tls: Arc<ServerConfig>) -> bool {
    let Ok(tls) = tokio_rustls::TlsAcceptor::from(tls).accept(peer).await else {
        return false;
    };
    let Ok(mut connection) = h2::server::handshake(tls).await else {
        return false;
    };
    let Some(Ok((request, mut response))) = connection.accept().await else {
        return false;
    };
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().authority().unwrap(), "target.invalid:443");
    assert_eq!(request.headers()["proxy-authorization"], "Basic dTpw");
    let exchange = async {
        let mut receive = request.into_body();
        let data = receive.data().await.unwrap().unwrap();
        assert_eq!(data.as_ref(), b"ping");
        receive.flow_control().release_capacity(data.len()).unwrap();
        response
            .send_response(http::Response::new(()), false)
            .unwrap()
            .send_data(bytes::Bytes::from_static(b"pong"), true)
            .unwrap();
        true
    };
    let completed = tokio::select! {
        completed = exchange => completed,
        _ = std::future::poll_fn(|cx| connection.poll_closed(cx)) => false,
    };
    connection.graceful_shutdown();
    let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
    completed
}

#[tokio::test]
async fn trusttunnel_h2_prior_knowledge_alpn_memory() {
    let chain = chain(false);
    let context = trusted(&chain);
    for &profile in crate::security::test_profiles() {
        for (alpn, bad_pin, expected) in [
            (Some(b"h2".as_slice()), false, true),
            (Some(b"http/1.1".as_slice()), false, false),
            (None, true, false),
            (None, false, true),
        ] {
            let config = Config::parse_yaml(
                b"proxies:\n  - name: tunnel\n    type: trusttunnel\n    server: fixture.invalid\n    port: 443\n    username: u\n    password: p\n    alpn: [h2, http/1.1]\n",
            )
            .unwrap();
            let ProxyProtocol::TrustTunnel(mut config) = config.proxies[0].protocol.clone() else {
                unreachable!();
            };
            config.tls.client_fingerprint = profile;
            if bad_pin {
                config.tls.certificate.fingerprint = Some([0xab; 32]);
                config.tls.certificate.skip_cert_verify = true;
            }
            let mut endpoint = server(&chain, &TLS13, false);
            Arc::get_mut(&mut endpoint).unwrap().alpn_protocols =
                alpn.map_or_else(Vec::new, |protocol| vec![protocol.to_vec()]);
            let (io, peer) = tokio::io::duplex(65536);
            let peers = TaskTracker::new();
            let peer = peers.spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), serve_h2(peer, endpoint)).await
            });
            let node = TrustTunnelOutbound::with_shared_security(
                &config,
                UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(io))))),
                &context,
                0,
                DEFAULT_TLS_BUFFER_LIMIT,
            )
            .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                let mut stream: BoxStream = node
                    .connect_stream(
                        StreamSession {
                            metadata: Default::default(),
                            inbound: InboundKind::InternalDns,
                            source: "127.0.0.1:1000".parse().unwrap(),
                            destination: Destination::Domain {
                                host: "target.invalid".into(),
                                port: 443,
                            },
                            sniffed_domain: None,
                        },
                        &EstablishContext::with_timeout(Duration::from_secs(3)),
                    )
                    .await
                    .map_err(io::Error::other)?
                    .io;
                stream.write_all(b"ping").await?;
                stream.flush().await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                assert_eq!(response, b"pong");
                stream.shutdown().await
            })
            .await;
            tokio::time::timeout(Duration::from_secs(3), node.shutdown())
                .await
                .unwrap();
            peers.close();
            peers.wait().await;
            let peer_completed = peer.await.unwrap().unwrap();
            assert!(
                result.is_ok(),
                "profile={profile:?}, negotiated={alpn:?}, bad_pin={bad_pin}: client timed out"
            );
            assert_eq!(
                result.as_ref().is_ok_and(|result| result.is_ok()),
                expected,
                "profile={profile:?}, negotiated={alpn:?}, bad_pin={bad_pin}, result={result:?}"
            );
            assert_eq!(peer_completed, expected);
        }
    }
}

#[tokio::test]
async fn standard_required_h2_still_rejects_absent_alpn_memory() {
    let chain = chain(false);
    for &profile in crate::security::test_profiles() {
        let client = StandardTlsClient::with_options(
            &trusted(&chain),
            "fixture.invalid",
            TlsClientOptions {
                client_fingerprint: profile,
                alpn: vec![b"h2".to_vec()],
                required_alpn: Some(b"h2".to_vec()),
                ..Default::default()
            },
            0,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
        .unwrap();
        assert!(!handshake(&client, server(&chain, &TLS13, false)).await.0);
    }
}
