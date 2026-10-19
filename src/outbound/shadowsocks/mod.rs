//! Official SS 2022 codec over Vole-owned TCP and UDP transports.
use super::{
    ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    server_destination,
};
use crate::{
    config::ShadowsocksOutboundConfig,
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{DatagramSession, Destination, StreamSession},
};
use async_trait::async_trait;
use shadowsocks::{ServerConfig, config::ServerType, context::Context};
use std::{io, sync::Arc};

mod datagram;
mod datagram_codec;
#[cfg(test)]
mod packet_io;
mod packet_window;
mod plugin;
mod stream;
mod uot;

#[derive(Clone)]
pub struct ShadowsocksOutbound {
    server: Destination,
    config: Arc<ServerConfig>,
    context: shadowsocks::context::SharedContext,
    upstream: UpstreamPath,
    uot: Option<Arc<uot::Owner>>,
    plugin: Option<Arc<plugin::Owner>>,
}

impl std::fmt::Debug for ShadowsocksOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksOutbound")
            .finish_non_exhaustive()
    }
}

impl ShadowsocksOutbound {
    pub fn new_with_path(
        config: &ShadowsocksOutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        Self::with_security(config, upstream, None, 0, 64 * 1024)
    }

    pub(crate) fn with_security(
        config: &ShadowsocksOutboundConfig,
        upstream: UpstreamPath,
        security: Option<&crate::security::SecurityContext>,
        sessions: usize,
        buffer: usize,
    ) -> io::Result<Self> {
        config.validate().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks configuration",
            )
        })?;
        let server = server_destination(&config.address, config.port)?;
        let plugin = config
            .plugin
            .as_ref()
            .map(|options| {
                plugin::Owner::new(
                    options,
                    &security.cloned().unwrap_or_default(),
                    sessions,
                    buffer,
                    config.port,
                )
            })
            .transpose()?
            .map(Arc::new);
        let method = config.cipher.as_str().parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported Shadowsocks cipher",
            )
        })?;
        let uot = config.udp_over_tcp.then(|| Arc::new(uot::Owner::default()));
        let config = ServerConfig::new(
            (config.address.clone(), config.port),
            config.password.clone(),
            method,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks credentials",
            )
        })?;
        Ok(Self {
            server,
            config: Arc::new(config),
            context: Context::new_shared(ServerType::Local),
            upstream,
            uot,
            plugin,
        })
    }
}

#[async_trait]
impl OutboundConnector for ShadowsocksOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let target = session.destination.clone();
        let io = if let Some(plugin) = &self.plugin {
            plugin
                .open(&self.upstream, &self.server, session, context)
                .await?
        } else {
            self.upstream
                .connect_server(session, &self.server, context)
                .await?
                .io
        };
        let stream =
            stream::SsStream::new(self.context.clone(), io, &self.config, address(&target));
        Ok(ConnectedStream {
            io: Box::new(stream),
            effective_peer: target,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if let Some(uot) = &self.uot {
            return uot.open(self, request, context).await;
        }
        let server = self.upstream.datagram_server(&self.server, context).await?;
        let maximum = request.max_response_payload_size();
        let wire_maximum = maximum.saturating_add(datagram::MAX_RESPONSE_HEADER);
        let inner = self
            .upstream
            .open_datagram(
                request.with_envelope(
                    datagram::request_header(&self.config).saturating_add(259 + 900),
                    usize::from(datagram::MAX_RESPONSE_HEADER),
                ),
                context,
            )
            .await?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(datagram::SsDatagram::new(
                inner,
                server,
                self.context.clone(),
                self.config.clone(),
                maximum,
                wire_maximum,
            )),
            request.budget(),
        ))
    }

    fn begin_shutdown(&self) {
        if let Some(plugin) = &self.plugin {
            plugin.begin_shutdown();
        }
        if let Some(uot) = &self.uot {
            uot.begin_shutdown();
        }
    }

    async fn shutdown(&self) {
        if let Some(plugin) = &self.plugin {
            plugin.shutdown().await;
        }
        if let Some(uot) = &self.uot {
            uot.shutdown().await;
        }
    }
}

#[async_trait]
impl Dispatcher for ShadowsocksOutbound {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        OutboundConnector::connect_stream(self, session, &EstablishContext::default())
            .await
            .map(|stream| stream.io)
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        OutboundConnector::open_datagram(
            self,
            DatagramRequest::new(session),
            &EstablishContext::default(),
        )
        .await
    }
}

fn address(target: &Destination) -> shadowsocks::relay::socks5::Address {
    match target {
        Destination::Ip(value) => (*value).into(),
        Destination::Domain { host, port } => (host.clone(), *port).into(),
    }
}

fn destination(target: shadowsocks::relay::socks5::Address) -> io::Result<Destination> {
    match target {
        shadowsocks::relay::socks5::Address::SocketAddress(value) if value.port() != 0 => {
            Ok(Destination::Ip(value))
        }
        shadowsocks::relay::socks5::Address::DomainNameAddress(host, port) => {
            Destination::domain(host, port)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Shadowsocks response address",
        )),
    }
}

fn safe_io(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "Shadowsocks stream operation failed")
}

#[cfg(test)]
mod tests;
