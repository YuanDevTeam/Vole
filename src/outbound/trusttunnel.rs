//! TrustTunnel CONNECT over supplied TLS/H2 IO. Physical sockets remain owned
//! by the shared Dialer; the node owns the pool and its synchronous stop barrier.
use crate::{
    config::{GrpcOptions, TrustTunnelOutboundConfig},
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    security::{
        SecurityContext, StandardTlsClient, TlsClientIdentity, TlsClientOptions, TlsVersions,
    },
    session::{Destination, StreamSession},
    transport::GrpcPool,
};
use async_trait::async_trait;
use base64::Engine;
use std::io;

pub struct TrustTunnelOutbound {
    server: Destination,
    upstream: UpstreamPath,
    tls: StandardTlsClient,
    authorization: String,
    pool: GrpcPool,
}

impl TrustTunnelOutbound {
    pub(crate) fn with_shared_security(
        config: &TrustTunnelOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let policy = &config.tls;
        let tls = StandardTlsClient::with_options(
            security,
            &policy.server_name,
            TlsClientOptions {
                ech: policy.ech.clone(),
                client_fingerprint: policy.client_fingerprint,
                versions: if policy.tls13_only {
                    TlsVersions::Tls13
                } else {
                    TlsVersions::Tls12And13
                },
                alpn: policy.alpn.clone(),
                required_alpn: policy.required_alpn.clone(),
                certificate: policy.certificate.clone(),
                identity: policy
                    .identity
                    .as_ref()
                    .map(|identity| {
                        TlsClientIdentity::from_pem(&identity.certificate, &identity.private_key)
                    })
                    .transpose()?,
            },
            sessions,
            buffer_limit,
        )?;
        // Stream counts are nonnegative. Negative signed thresholds therefore
        // have the same comparison semantics as zero, after all-zero defaults
        // were resolved by the configuration consumer.
        let threshold = |value: i64| usize::try_from(value.max(0)).unwrap_or(usize::MAX);
        Ok(Self {
            server: server_destination(&config.address, config.port)?,
            upstream,
            tls,
            authorization: format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", config.username, config.password))
            ),
            pool: GrpcPool::new(GrpcOptions {
                max_connections: threshold(config.pool.max_connections),
                min_streams: threshold(config.pool.min_streams),
                max_streams: threshold(config.pool.max_streams),
                ..Default::default()
            }),
        })
    }
}

fn connect_request(target: &Destination, authorization: &str) -> io::Result<http::Request<()>> {
    let authority = match target {
        Destination::Ip(address) => address.to_string(),
        Destination::Domain { host, port } => format!("{host}:{port}"),
    };
    // CONNECT uses only :authority. HTTP/2 elides :scheme and :path.
    let uri = http::Uri::builder()
        .authority(authority)
        .build()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("proxy-authorization", authorization)
        .header(
            "user-agent",
            format!(
                "{} Vole/{}",
                std::env::consts::OS,
                env!("CARGO_PKG_VERSION")
            ),
        )
        .body(())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

#[async_trait]
impl OutboundConnector for TrustTunnelOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let target = session.destination.clone();
        let request = connect_request(&target, &self.authorization)?;
        let io = context
            .run_io(
                "TrustTunnel HTTP/2 CONNECT",
                self.pool
                    .open_connect(request, context.deadline(), || async {
                        let raw = self
                            .upstream
                            .connect_server(session, &self.server, context)
                            .await
                            .map_err(io::Error::other)?;
                        self.tls.connect_with_context(raw.io, context).await
                    }),
            )
            .await?;
        Ok(ConnectedStream {
            io,
            effective_peer: target,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    fn begin_shutdown(&self) {
        self.pool.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.pool.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::observation::ResourceProbe;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::task::TaskTracker;

    #[tokio::test]
    async fn trusttunnel_h2_connect_is_raw_deferred_pooled_and_stopped() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peers = TaskTracker::new();
                let connections = Arc::new(AtomicUsize::new(0));
                let pool = GrpcPool::new(GrpcOptions::default());
                let make_connection = || {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (client, peer) = tokio::io::duplex(64 * 1024);
                    let streams = peers.clone();
                    peers.spawn(async move {
                        let mut connection = h2::server::handshake(peer).await.unwrap();
                        while let Some(Ok((request, mut response))) = connection.accept().await {
                            assert_eq!(request.method(), http::Method::CONNECT);
                            assert_eq!(request.uri().authority().unwrap(), "example.invalid:443");
                            assert_eq!(request.headers()["proxy-authorization"], "Basic dTpw");
                            assert!(!request.headers().contains_key("content-type"));
                            streams.spawn(async move {
                                let mut receive = request.into_body();
                                let data = receive.data().await.unwrap().unwrap();
                                assert_eq!(data.as_ref(), b"unframed-client-first");
                                receive.flow_control().release_capacity(data.len()).unwrap();
                                let mut send = response
                                    .send_response(http::Response::new(()), false)
                                    .unwrap();
                                send.send_data(data, false).unwrap();
                                while receive.data().await.is_some_and(|data| data.is_ok()) {}
                            });
                        }
                    });
                    async move { Ok(Box::new(client) as crate::dispatch::BoxStream) }
                };
                let target = Destination::Domain {
                    host: "example.invalid".into(),
                    port: 443,
                };
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut first = pool
                    .open_connect(
                        connect_request(&target, "Basic dTpw").unwrap(),
                        deadline,
                        make_connection,
                    )
                    .await
                    .unwrap();
                let mut second = pool
                    .open_connect(
                        connect_request(&target, "Basic dTpw").unwrap(),
                        deadline,
                        make_connection,
                    )
                    .await
                    .unwrap();
                assert_eq!(connections.load(Ordering::SeqCst), 1);
                for stream in [&mut first, &mut second] {
                    stream.write_all(b"unframed-client-first").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut response = [0; 21];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"unframed-client-first");
                }
                first.shutdown().await.unwrap();
                pool.shutdown().await;
                assert!(second.write_all(b"after-stop").await.is_err());
                drop((first, second));
                peers.close();
                peers.wait().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
}
