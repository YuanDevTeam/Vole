//! A named direct route retains its own physical policy and direct DNS role.
use std::task::{Context, Poll};

use async_trait::async_trait;

use crate::{
    dialer::Dialer,
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    session::{Datagram, Destination, StreamSession},
};

use super::{
    ConnectedStream, DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest, DirectOutbound, EstablishContext,
    OutboundConnector,
};

pub(crate) struct NamedDirectOutbound {
    dialer: Dialer,
    direct: DirectOutbound,
}

impl NamedDirectOutbound {
    pub(crate) fn new(dialer: Dialer) -> Self {
        Self {
            direct: DirectOutbound::new(dialer.clone()),
            dialer,
        }
    }
}

#[async_trait]
impl OutboundConnector for NamedDirectOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let endpoint = context
            .resolution()
            .with_physical_dialer(&self.dialer)
            .resolve_direct(&session.destination, context.deadline())
            .await?;
        let stream = context
            .run_io(
                "direct TCP connect",
                self.dialer
                    .connect_server_tcp(&endpoint, context.deadline()),
            )
            .await?;
        let effective_peer = Destination::Ip(stream.address);
        Ok(ConnectedStream {
            io: stream.io,
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let inner = self.direct.open_datagram(request, context).await?;
        Ok(Box::new(NamedDirectDatagram {
            inner,
            resolution: context.resolution(),
        }))
    }
}

struct NamedDirectDatagram {
    inner: Box<dyn DatagramTransport>,
    resolution: ResolutionContext,
}

#[async_trait]
impl DatagramTransport for NamedDirectDatagram {
    fn supports_shared_destinations(&self) -> bool {
        self.inner.supports_shared_destinations()
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.inner.payload_budget(peer)
    }

    fn send_owned(
        &mut self,
        packet: Datagram,
    ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
        if matches!(packet.remote, Destination::Ip(_)) {
            self.inner.send_owned(packet)
        } else {
            Err(packet)
        }
    }

    async fn send(&mut self, mut packet: Datagram) -> Result<(), DispatchError> {
        if matches!(packet.remote, Destination::Ip(_)) {
            return self.inner.send(packet).await;
        }
        let endpoint = self
            .resolution
            .resolve_direct(
                &packet.remote,
                tokio::time::Instant::now() + DEFAULT_ESTABLISH_TIMEOUT,
            )
            .await?;
        packet.remote = Destination::Ip(
            endpoint
                .addresses
                .first()
                .copied()
                .ok_or(DispatchError::HostUnreachable)?,
        );
        self.inner.send(packet).await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.inner.receive().await
    }

    fn supports_poll_receive(&self) -> bool {
        self.inner.supports_poll_receive()
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        self.inner.poll_receive(context, scratch)
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.inner.close().await
    }
}
