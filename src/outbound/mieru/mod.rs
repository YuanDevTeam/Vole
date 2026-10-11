//! Native Mieru client. Carriers use only the shared configured upstream path.
mod crypto;
mod low_entropy;
mod packet;
pub(crate) mod pattern;
mod reliability;
mod stream;
mod tcp;
mod udp;
mod wire;
use crate::{
    config::{MieruHandshake, MieruOutboundConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    },
    session::{Destination, StreamSession},
    socks5,
};
use async_trait::async_trait;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

pub struct MieruOutbound {
    client: tcp::Client,
    udp: bool,
    handshake: MieruHandshake,
}
impl std::fmt::Debug for MieruOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruOutbound")
            .field("udp", &self.udp)
            .finish_non_exhaustive()
    }
}
impl MieruOutbound {
    pub fn new(
        config: &MieruOutboundConfig,
        upstream: UpstreamPath,
        stream_buffer_capacity: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            client: tcp::Client::new(config, upstream, stream_buffer_capacity)?,
            udp: config.udp,
            handshake: config.handshake_mode,
        })
    }
    async fn connect(
        &self,
        session: StreamSession,
        command: u8,
        context: &EstablishContext,
    ) -> io::Result<BoxStream> {
        let target = session.destination.clone();
        let raw = self.client.open(session, context).await?;
        let stream = match self.handshake {
            MieruHandshake::Standard => {
                stream::Stream::standard(raw, &target, command, context.deadline()).await?
            }
            MieruHandshake::NoWait => stream::Stream::no_wait(raw, &target, command)?,
        };
        Ok(Box::new(stream))
    }
}
#[async_trait]
impl OutboundConnector for MieruOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let target = session.destination.clone();
        let io = context
            .run_io(
                "Mieru business connection",
                self.connect(session, socks5::COMMAND_CONNECT, context),
            )
            .await?;
        Ok(ConnectedStream {
            io,
            effective_peer: target,
        })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if !self.udp {
            return Err(DispatchError::NotAllowed);
        }
        // The official UDP associate server ignores this target. Each packet
        // supplies its own destination inside the shared SOCKS UDP envelope.
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: Destination::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
            sniffed_domain: None,
        };
        let io = context
            .run_io(
                "Mieru UDP associate",
                self.connect(session, socks5::COMMAND_UDP_ASSOCIATE, context),
            )
            .await?;
        let transport = packet::PacketTransport::new(
            io,
            &request,
            context,
            self.client.cancellation(),
            |reader| self.client.spawn(reader),
        )?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(transport),
            request.budget(),
        ))
    }
    fn begin_shutdown(&self) {
        self.client.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}
#[cfg(test)]
mod tests;
