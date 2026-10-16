use super::{
    BodyCipher, BodyOptions, ClientHandshake, Command, MAX_PACKET_BYTES, VmessDatagram,
    VmessIdentity, VmessStream,
};
use crate::{
    config::{VmessCipher, VmessOutboundConfig, VmessPacketEncoding, VmessTransport},
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        owned_stream::OwnedStream, server_destination,
    },
    resources::observation::{self, ResourceKind},
    security::{
        SecurityContext, StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsClientOptions,
    },
    session::{Datagram, Destination, StreamSession},
    transport::{GrpcPool, connect_websocket, http_obfs, legacy_h2},
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tokio::{io::AsyncWriteExt, time::Instant};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

struct SessionOptions {
    identity: VmessIdentity,
    body: BodyOptions,
    transport: VmessTransport,
}

pub struct VmessOutbound {
    server: Destination,
    upstream: UpstreamPath,
    tls: Option<StandardTlsClient>,
    options: Arc<SessionOptions>,
    encoding: VmessPacketEncoding,
    grpc_pool: Option<GrpcPool>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
}

impl std::fmt::Debug for VmessOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessOutbound").finish_non_exhaustive()
    }
}

impl VmessOutbound {
    pub fn new_with_path(config: &VmessOutboundConfig, upstream: UpstreamPath) -> io::Result<Self> {
        Self::with_shared_security(
            config,
            upstream,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            64 * 1024,
        )
    }
    pub(crate) fn with_shared_security(
        config: &VmessOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        sessions: usize,
        buffer: usize,
    ) -> io::Result<Self> {
        let cipher = match config.cipher {
            VmessCipher::Auto => BodyCipher::Auto,
            VmessCipher::Aes128Gcm => BodyCipher::Aes128Gcm,
            VmessCipher::Chacha20Poly1305 => BodyCipher::Chacha20Poly1305,
            VmessCipher::None => BodyCipher::None,
        };
        let tls = config
            .tls
            .as_ref()
            .map(|tls| {
                StandardTlsClient::with_options(
                    security,
                    &config.server_name,
                    TlsClientOptions::from_policy(tls, config.transport.required_alpn())?,
                    sessions,
                    buffer,
                )
            })
            .transpose()?;
        Ok(Self {
            server: server_destination(&config.address, config.port)?,
            upstream,
            tls,
            options: Arc::new(SessionOptions {
                identity: VmessIdentity::new(config.id),
                body: BodyOptions::new(cipher, config.global_padding, config.authenticated_length)?,
                transport: config.transport.clone(),
            }),
            encoding: config.packet_encoding,
            grpc_pool: match &config.transport {
                VmessTransport::Grpc { options, .. } => Some(GrpcPool::new(options.clone())),
                _ => None,
            },
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
        })
    }
    async fn connect_transport(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?
            .io;
        if let Some(tls) = &self.tls {
            context
                .run_io(
                    "VMess TLS handshake",
                    tls.connect_with_context(raw, context),
                )
                .await
        } else {
            Ok(raw)
        }
    }
    async fn prepare(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<PreparedStream, DispatchError> {
        if Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        tokio::select! { biased;
            ()=self.cancellation.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                let raw=if let VmessTransport::Grpc { uri, .. }=&self.options.transport {
                    self.grpc_pool.as_ref().expect("gRPC pool").open(uri,context.deadline(),||async {
                        self.connect_transport(session,context).await.map_err(io::Error::other)
                    }).await?
                } else { self.connect_transport(session,context).await? };
                let token=self.cancellation.child_token();
                Ok(PreparedStream { raw:Box::new(OwnedStream::new(raw,token.clone())),options:self.options.clone(),deadline:context.deadline(),tasks:self.tasks.clone(),token })
            }=>result,
        }
    }
}

struct PreparedStream {
    raw: BoxStream,
    options: Arc<SessionOptions>,
    deadline: Instant,
    tasks: TaskTracker,
    token: CancellationToken,
}
impl PreparedStream {
    async fn finish(
        self,
        command: Command,
        target: &Destination,
    ) -> Result<VmessStream, DispatchError> {
        if Instant::now() >= self.deadline {
            return Err(DispatchError::TimedOut);
        }
        let handshake =
            ClientHandshake::new(&self.options.identity, command, target, self.options.body)?;
        let whole_close = matches!(
            self.options.transport,
            VmessTransport::Grpc { .. } | VmessTransport::Http { .. } | VmessTransport::H2 { .. }
        );
        let deadline = self.deadline;
        let result = tokio::time::timeout_at(deadline, async {
            let mut raw = self.raw;
            let mut sent = false;
            let mut driver = None;
            match &self.options.transport {
                VmessTransport::Tcp => {}
                VmessTransport::WebSocket { .. } => {
                    raw = connect_websocket(
                        raw,
                        &self
                            .options
                            .transport
                            .websocket_options()?
                            .expect("validated websocket"),
                        handshake.request(),
                        deadline,
                    )
                    .await?;
                    sent = true;
                }
                VmessTransport::Http { .. } => {
                    raw = http_obfs(
                        raw,
                        &self
                            .options
                            .transport
                            .http_options()?
                            .expect("validated http"),
                        handshake.request(),
                        deadline,
                    )
                    .await?;
                    sent = true;
                }
                // prepare already opened this logical gRPC stream. Authentication
                // is fresh here, without wrapping or dialing the transport again.
                VmessTransport::Grpc { .. } => {}
                VmessTransport::H2 { uris } => {
                    let uri = &uris[rand::random_range(0..uris.len())];
                    let connected = legacy_h2(raw, uri, deadline).await?;
                    raw = connected.0;
                    driver = Some(connected.1);
                }
            }
            if let Some(driver) = driver {
                let token = self.token.clone();
                let observation = observation::track(ResourceKind::Task);
                self.tasks.spawn(observation::bind(async move {
                    let _observation = observation;
                    token.cancelled().await;
                    let _ = driver.stop().await;
                }));
            }
            // Dropping setup after a partial header must also stop an H2 driver.
            let guard = self.token.clone().drop_guard();
            if !sent {
                raw.write_all(handshake.request()).await?;
                raw.flush().await?;
            }
            let stream = VmessStream::new(raw, handshake, deadline);
            guard.disarm();
            Ok::<_, io::Error>(if whole_close {
                stream.with_whole_close()
            } else {
                stream
            })
        })
        .await
        .map_err(|_| DispatchError::TimedOut)??;
        Ok(result)
    }
}

#[async_trait]
impl OutboundConnector for VmessOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let prepared = self.prepare(session, context).await?;
        let token = prepared.token.clone();
        let stream = prepared.finish(Command::Tcp, &effective_peer).await?;
        Ok(ConnectedStream {
            io: Box::new(OwnedStream::new(Box::new(stream), token)),
            effective_peer,
        })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: self.server.clone(),
            sniffed_domain: None,
        };
        // Select the physical upstream once now. Raw UDP learns its authenticated
        // target from the first send, under this same absolute setup deadline.
        let prepared = self.prepare(session, context).await?;
        let token = prepared.token.clone();
        let budget = request.budget().intersect(DatagramBudget::new(
            MAX_PACKET_BYTES as u16,
            MAX_PACKET_BYTES as u16,
        ));
        let (pending, inner) = if self.encoding == VmessPacketEncoding::Raw {
            (Some(prepared), None)
        } else {
            let (command, magic) = if self.encoding == VmessPacketEncoding::Xudp {
                (Command::Mux, "v1.mux.cool")
            } else {
                (Command::Udp, "sp.packet-addr.v2fly.arpa")
            };
            let stream = prepared
                .finish(command, &Destination::domain(magic, 443)?)
                .await?;
            let inner: Box<dyn DatagramTransport> = if self.encoding == VmessPacketEncoding::Xudp {
                Box::new(crate::xudp::XudpTransport::with_budget(
                    Box::new(stream),
                    [0; 8],
                    budget,
                ))
            } else {
                Box::new(VmessDatagram::packet_addr(
                    stream,
                    budget,
                    context.resolution(),
                ))
            };
            (None, Some(inner))
        };
        Ok(crate::dispatch::bound_datagram(
            Box::new(SessionDatagram {
                pending,
                inner,
                budget,
                token,
            }),
            request.budget(),
        ))
    }
    fn begin_shutdown(&self) {
        self.cancellation.cancel();
        if let Some(pool) = &self.grpc_pool {
            pool.begin_shutdown();
        }
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.close();
        self.tasks.wait().await;
        if let Some(pool) = &self.grpc_pool {
            pool.shutdown().await;
        }
    }
}
impl Drop for VmessOutbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct SessionDatagram {
    pending: Option<PreparedStream>,
    inner: Option<Box<dyn DatagramTransport>>,
    budget: DatagramBudget,
    token: CancellationToken,
}
impl Drop for SessionDatagram {
    fn drop(&mut self) {
        self.token.cancel();
    }
}
#[async_trait]
impl DatagramTransport for SessionDatagram {
    fn supports_shared_destinations(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.supports_shared_destinations())
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.inner.as_ref().map_or(self.budget, |inner| {
            self.budget.intersect(inner.payload_budget(peer))
        })
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if datagram.payload.is_empty()
            || datagram.remote.port() == 0
            || datagram.payload.len()
                > usize::from(self.payload_budget(&datagram.remote).transmit())
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        tokio::select! {biased;
            ()=self.token.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                if let Some(prepared)=self.pending.take() {
                    let stream=prepared.finish(Command::Udp,&datagram.remote).await?;
                    self.inner=Some(Box::new(VmessDatagram::raw(stream,datagram.remote.clone(),self.budget)));
                }
                self.inner.as_mut().ok_or(DispatchError::NotAllowed)?.send(datagram).await
            }=>result,
        }
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let pending = self.pending.is_some();
        let inner = &mut self.inner;
        tokio::select! {biased;
            ()=self.token.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                if pending { return std::future::pending().await; }
                inner.as_mut().ok_or(DispatchError::NotAllowed)?.receive().await
            }=>result,
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.token.cancel();
        self.pending.take();
        self.inner.take();
        Ok(())
    }
}
