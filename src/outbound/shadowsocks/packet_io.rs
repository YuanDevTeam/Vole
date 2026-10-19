//! One bounded packet handoff between the official codec and Vole async IO.
//! This adapter owns no socket, task, or retry queue.
use bytes::Bytes;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

use super::datagram::MAX_WIRE_PACKET;

#[derive(Clone, Default)]
pub(crate) struct PacketIo(Arc<Mutex<Option<Bytes>>>);

impl PacketIo {
    pub(crate) fn put(&self, packet: Bytes) -> io::Result<()> {
        if packet.len() > MAX_WIRE_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SS UDP packet exceeds wire limit",
            ));
        }
        let mut slot = self
            .0
            .lock()
            .map_err(|_| io::Error::other("SS packet handoff poisoned"))?;
        if slot.is_some() {
            return Err(io::Error::other("SS packet handoff is occupied"));
        }
        *slot = Some(packet);
        Ok(())
    }

    pub(crate) fn take(&self) -> io::Result<Bytes> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("SS packet handoff poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("SS packet handoff is empty"))
    }
}

impl DatagramSend for PacketIo {
    fn poll_send(&self, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(self.put(Bytes::copy_from_slice(data)).map(|()| data.len()))
    }
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        data: &[u8],
        _: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.poll_send(cx, data)
    }
    fn poll_send_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl DatagramReceive for PacketIo {
    fn poll_recv(&self, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.take().and_then(|packet| {
            if packet.len() > buf.remaining() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SS packet handoff buffer too short",
                ));
            }
            buf.put_slice(&packet);
            Ok(())
        }))
    }
    fn poll_recv_from(
        &self,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SS packet handoff uses connected IO",
        )))
    }
    fn poll_recv_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
