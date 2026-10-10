use std::io;

use crate::outbound::owned_stream::OwnedStream;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{TrojanOutboundConfig, TrojanTransport},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    security::{
        SecurityContext, StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsClientOptions,
    },
    session::{Destination, StreamSession},
    transport::{GrpcPool, WebSocketOptions, connect_websocket},
};

use super::{TrojanAuth, TrojanCommand, TrojanDatagram};

pub struct TrojanOutbound {
    server: Destination,
    upstream: UpstreamPath,
    auth: TrojanAuth,
    tls: StandardTlsClient,
    cancellation: CancellationToken,
    transport: Transport,
}

enum Transport {
    Tcp,
    WebSocket(Box<WebSocketOptions>),
    Grpc { uri: String, pool: GrpcPool },
}

impl std::fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanOutbound").finish_non_exhaustive()
    }
}

impl TrojanOutbound {
    pub fn new_with_path(
        config: &TrojanOutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        Self::with_shared_security(
            config,
            upstream,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            64 * 1024,
        )
    }

    pub(crate) fn with_shared_security(
        config: &TrojanOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            transport: match &config.transport {
                TrojanTransport::Tcp => Transport::Tcp,
                TrojanTransport::WebSocket { .. } => Transport::WebSocket(Box::new(
                    config
                        .transport
                        .websocket_options()?
                        .expect("WebSocket config"),
                )),
                TrojanTransport::Grpc { uri, options } => Transport::Grpc {
                    uri: uri.clone(),
                    pool: GrpcPool::duplex(options.clone()),
                },
            },
            server: server_destination(&config.address, config.port)?,
            upstream,
            auth: TrojanAuth::new(&config.password)?,
            tls: StandardTlsClient::with_options(
                security,
                &config.server_name,
                TlsClientOptions::from_policy(&config.tls, config.transport.required_alpn())?,
                resumption_sessions,
                buffer_limit,
            )?,
            cancellation: CancellationToken::new(),
        })
    }

    async fn connect_tls(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?;
        context
            .run_io("Trojan TLS handshake", self.tls.connect(raw.io))
            .await
    }

    async fn connect(
        &self,
        session: StreamSession,
        command: TrojanCommand,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        // timeout_at may poll an immediately-ready future before its timer.
        // A previously expired chain deadline must not even create a socket.
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let request = self.auth.request(command, &session.destination)?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(DispatchError::NotAllowed),
            connected = async {
                let token = self.cancellation.child_token();
                let setup_guard = token.clone().drop_guard();
                let stream = if let Transport::Grpc { uri, pool } = &self.transport {
                    pool.open(uri, context.deadline(), || async {
                        self.connect_tls(session, context).await.map_err(io::Error::other)
                    }).await?
                } else {
                    let stream = self.connect_tls(session, context).await?;
                    if let Transport::WebSocket(options) = &self.transport {
                        context.run_io("Trojan WebSocket upgrade",connect_websocket(stream,options,&request,context.deadline())).await?
                    } else { stream }
                };
                let mut stream = OwnedStream::new(stream, token);
                setup_guard.disarm();
                if !matches!(self.transport,Transport::WebSocket(_)) {
                    context.run_io("Trojan request header", async {
                    stream.write_all(&request).await?;
                    stream.flush().await
                    }).await?;
                }
                Ok(Box::new(stream) as BoxStream)
            } => connected,
        }
    }
}

#[async_trait]
impl OutboundConnector for TrojanOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        Ok(ConnectedStream {
            io: self.connect(session, TrojanCommand::Tcp, context).await?,
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        // UDP destinations live in individual frames, not this request header.
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: Destination::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 1))),
            sniffed_domain: None,
        };
        let stream = self.connect(session, TrojanCommand::Udp, context).await?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(TrojanDatagram::new(stream, request.budget())),
            request.budget(),
        ))
    }

    fn begin_shutdown(&self) {
        self.cancellation.cancel();
        if let Transport::Grpc { pool, .. } = &self.transport {
            pool.begin_shutdown();
        }
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        if let Transport::Grpc { pool, .. } = &self.transport {
            pool.shutdown().await;
        }
    }
}

impl Drop for TrojanOutbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
