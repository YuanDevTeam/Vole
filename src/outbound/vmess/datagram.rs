use std::{
    io,
    task::{Context, Poll, ready},
};

use super::{MAX_PACKET_BYTES, VmessStream};
use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::{
        DEFAULT_ESTABLISH_TIMEOUT,
        address::{decode_packet_addr, encode_packet_addr},
    },
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::BytesMut;

enum Encoding {
    Raw(Destination),
    PacketAddr(ResolutionContext),
}

/// One VMess UDP command, with intact datagram boundaries. Raw commands are
/// bound to their authenticated request destination; packetaddr is IP-only.
/// Dropping a partially sent packet poisons the association, while incremental
/// reads retain their state in VmessStream. No task, socket or system DNS here.
pub struct VmessDatagram {
    stream: Option<VmessStream>,
    encoding: Encoding,
    budget: DatagramBudget,
}

impl VmessDatagram {
    pub fn raw(stream: VmessStream, peer: Destination, budget: DatagramBudget) -> Self {
        Self {
            stream: Some(stream),
            encoding: Encoding::Raw(peer),
            budget,
        }
    }
    pub fn packet_addr(
        stream: VmessStream,
        budget: DatagramBudget,
        resolution: ResolutionContext,
    ) -> Self {
        Self {
            stream: Some(stream),
            encoding: Encoding::PacketAddr(resolution),
            budget,
        }
    }
    fn check(&self) -> io::Result<()> {
        if self.stream.is_none() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

#[async_trait]
impl DatagramTransport for VmessDatagram {
    fn supports_shared_destinations(&self) -> bool {
        // Aggregating encrypted bodies exhausts the 16-bit nonce sequence
        // sooner; no transparent UDP association migration is available.
        matches!(self.encoding, Encoding::PacketAddr(_))
            && self
                .stream
                .as_ref()
                .is_some_and(|stream| !stream.uses_body_nonce())
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        let overhead = match (&self.encoding, peer) {
            (Encoding::Raw(_), _) => 0,
            (_, Destination::Ip(address)) if address.is_ipv4() => 7,
            _ => 19,
        };
        let maximum = (MAX_PACKET_BYTES - overhead) as u16;
        self.budget.intersect(DatagramBudget::new(maximum, maximum))
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.check()?;
        if datagram.payload.is_empty()
            || datagram.payload.len()
                > usize::from(self.payload_budget(&datagram.remote).transmit())
            || datagram.remote.port() == 0
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut packet = BytesMut::with_capacity(19 + datagram.payload.len());
        match &self.encoding {
            Encoding::Raw(peer) => {
                if peer != &datagram.remote {
                    return Err(DispatchError::NotAllowed);
                }
            }
            Encoding::PacketAddr(resolution) => {
                let peer = resolution
                    .resolve_ip(
                        &datagram.remote,
                        tokio::time::Instant::now() + DEFAULT_ESTABLISH_TIMEOUT,
                    )
                    .await?;
                encode_packet_addr(&peer.into(), &mut packet)?;
            }
        }
        packet.extend_from_slice(&datagram.payload);
        // Taking ownership across the non-cancellation-safe write makes a
        // cancelled/failed partial frame close IO immediately, even if the
        // caller retains the datagram transport without polling it again.
        let mut stream = self.stream.take().expect("checked open");
        stream.send_packet(&packet).await?;
        self.stream = Some(stream);
        Ok(())
    }

    fn supports_poll_receive(&self) -> bool {
        true
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        _scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        self.check()?;
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            let received = ready!(
                self.stream
                    .as_mut()
                    .expect("checked open")
                    .poll_packet(context)
            );
            let packet = match received {
                Ok(Some(packet)) => packet,
                Ok(None) => {
                    self.stream.take();
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                }
                Err(error) => {
                    self.stream.take();
                    return Poll::Ready(Err(error.into()));
                }
            };
            let (remote, consumed) = match &self.encoding {
                Encoding::Raw(peer) => (peer.clone(), 0),
                Encoding::PacketAddr(_) => match decode_packet_addr(&packet) {
                    Ok(address) => address,
                    Err(error) => {
                        self.stream.take();
                        return Poll::Ready(Err(error.into()));
                    }
                },
            };
            let payload = packet.slice(consumed..);
            if payload.len() <= usize::from(self.payload_budget(&remote).receive()) {
                return Poll::Ready(Ok(Datagram {
                    remote,
                    payload,
                    sniffed_domain: None,
                }));
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let mut scratch = Vec::new();
        std::future::poll_fn(|context| self.poll_receive(context, &mut scratch)).await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.stream.take();
        Ok(())
    }
}
