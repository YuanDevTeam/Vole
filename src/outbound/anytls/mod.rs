mod client;
mod frame;
mod padding;
mod session;
mod stream;

use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    },
    session::{Destination, StreamSession},
};

use super::uot::magic_destination;
use client::{AnyTlsClient, SessionDialer};

pub use stream::AnyTlsStream;

#[async_trait]
pub trait AnyTlsTlsConnector: Send + Sync {
    async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream>;
}

#[async_trait]
impl AnyTlsTlsConnector for crate::security::StandardTlsClient {
    async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        crate::security::StandardTlsClient::connect(self, stream).await
    }
}

struct OutboundSessionDialer {
    server: Destination,
    upstream: UpstreamPath,
    tls: Arc<dyn AnyTlsTlsConnector>,
}

#[async_trait]
impl SessionDialer for OutboundSessionDialer {
    async fn connect(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?;
        context
            .run_io("AnyTLS TLS handshake", self.tls.connect(raw.io))
            .await
    }
}

#[derive(Clone)]
pub struct AnyTlsLifecycle {
    client: Arc<AnyTlsClient>,
}

impl std::fmt::Debug for AnyTlsLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsLifecycle")
            .finish_non_exhaustive()
    }
}

impl AnyTlsLifecycle {
    pub fn begin_shutdown(&self) {
        self.client.begin_shutdown();
    }

    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}

#[derive(Clone)]
pub struct AnyTlsOutbound {
    client: Arc<AnyTlsClient>,
}

impl std::fmt::Debug for AnyTlsOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsOutbound")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl AnyTlsOutbound {
    pub fn new(
        server: Destination,
        upstream: UpstreamPath,
        password: impl Into<String>,
        tls: Arc<dyn AnyTlsTlsConnector>,
        stream_buffer_capacity: usize,
    ) -> io::Result<Self> {
        Self::with_session_options(
            server,
            upstream,
            password,
            tls,
            stream_buffer_capacity,
            crate::config::AnyTlsSessionOptions::default(),
        )
    }

    pub fn with_session_options(
        server: Destination,
        upstream: UpstreamPath,
        password: impl Into<String>,
        tls: Arc<dyn AnyTlsTlsConnector>,
        stream_buffer_capacity: usize,
        options: crate::config::AnyTlsSessionOptions,
    ) -> io::Result<Self> {
        if server.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS server port is zero",
            ));
        }
        let dialer: Arc<dyn SessionDialer> = Arc::new(OutboundSessionDialer {
            server,
            upstream,
            tls,
        });
        let password = password.into();
        Ok(Self {
            client: AnyTlsClient::with_options(dialer, &password, stream_buffer_capacity, options)?,
        })
    }

    pub fn lifecycle(&self) -> AnyTlsLifecycle {
        AnyTlsLifecycle {
            client: self.client.clone(),
        }
    }

    pub fn begin_shutdown(&self) {
        self.client.begin_shutdown();
    }

    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}

#[async_trait]
impl OutboundConnector for AnyTlsOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let stream = self
            .client
            .open_stream(session, &effective_peer, context)
            .await?;
        Ok(ConnectedStream {
            io: Box::new(stream),
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let stream_session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: magic_destination(),
            sniffed_domain: None,
        };
        let stream = self
            .client
            .open_stream(stream_session, &magic_destination(), context)
            .await?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(
                self.client
                    .start_uot(stream, request.max_response_payload_size())?,
            ),
            request.budget(),
        ))
    }

    fn begin_shutdown(&self) {
        AnyTlsOutbound::begin_shutdown(self);
    }

    async fn shutdown(&self) {
        AnyTlsOutbound::shutdown(self).await;
    }
}
