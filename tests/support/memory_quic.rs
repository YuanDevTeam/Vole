//! Memory-only UDP peer shared by protocol regressions; never opens a socket.
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};
use tokio::sync::mpsc;
use vole::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector},
    session::{Datagram, Destination, StreamSession},
};

pub struct MemoryPackets {
    pub send: mpsc::Sender<Bytes>,
    pub receive: mpsc::Receiver<Bytes>,
    pub remote: SocketAddr,
}
#[async_trait]
impl DatagramTransport for MemoryPackets {
    fn supports_shared_destinations(&self) -> bool {
        false
    }

    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1400, 1400)
    }
    fn send_owned(
        &mut self,
        packet: Datagram,
    ) -> Result<vole::dispatch::OwnedDatagramSend, Datagram> {
        assert_eq!(packet.remote, self.remote.into());
        let sender = self.send.clone();
        Ok(Box::pin(async move {
            sender
                .send(packet.payload)
                .await
                .map_err(|_| DispatchError::NotAllowed)
        }))
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        assert_eq!(packet.remote, self.remote.into());
        self.send
            .send(packet.payload)
            .await
            .map_err(|_| DispatchError::NotAllowed)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        Ok(Datagram {
            remote: self.remote.into(),
            payload: self.receive.recv().await.ok_or(DispatchError::NotAllowed)?,
            sniffed_domain: None,
        })
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.receive.close();
        Ok(())
    }
}
pub struct MemoryUpstream<T>(pub Mutex<Option<T>>);
#[async_trait]
impl<T: DatagramTransport + 'static> OutboundConnector for MemoryUpstream<T> {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(self.0.lock().unwrap().take().unwrap()))
    }
}

// The passive fixture uses Quinn's socket seam, not Vole's client-only
// adapter (which intentionally waits for its first authorized outbound send).
#[derive(Debug)]
pub struct PeerSocket {
    pub send: mpsc::Sender<Bytes>,
    pub receive: Mutex<mpsc::Receiver<Bytes>>,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}
#[derive(Debug)]
struct Writable(Mutex<tokio_util::sync::PollSender<Bytes>>);
impl quinn::UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock().unwrap();
        if ready!(sender.poll_reserve(cx)).is_ok() {
            sender.abort_send();
        }
        Poll::Ready(Ok(()))
    }
}
impl quinn::AsyncUdpSocket for PeerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(Writable(Mutex::new(tokio_util::sync::PollSender::new(
            self.send.clone(),
        ))))
    }
    fn try_send(&self, packet: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        assert_eq!(packet.destination, self.remote);
        match self.send.try_send(Bytes::copy_from_slice(packet.contents)) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // An unconnected UDP socket has no peer EOF. A closed memory link
        // becomes silent, not a local socket failure: otherwise Quinn's
        // endpoint driver can exit before notifying an existing wait_idle.
        let Some(packet) = ready!(self.receive.lock().unwrap().poll_recv(cx)) else {
            return Poll::Pending;
        };
        bufs[0][..packet.len()].copy_from_slice(&packet);
        meta[0] = quinn::udp::RecvMeta {
            addr: self.remote,
            len: packet.len(),
            stride: packet.len(),
            ecn: None,
            dst_ip: Some(self.local.ip()),
        };
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}
