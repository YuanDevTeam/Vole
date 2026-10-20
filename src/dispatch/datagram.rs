use std::io;

use super::{DatagramTransport, DispatchError};
use crate::packet::IpVersion;
use crate::session::{Datagram, Destination};

pub const QUIC_MIN_PAYLOAD_BYTES: u16 = 1200;

/// Directional payload ceilings at one datagram seam, excluding its envelope.
/// Zero means no nonempty payload fits, not permission to remove a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramBudget {
    transmit: u16,
    receive: u16,
}

impl DatagramBudget {
    pub const fn new(transmit: u16, receive: u16) -> Self {
        Self { transmit, receive }
    }
    pub const fn transmit(self) -> u16 {
        self.transmit
    }
    pub const fn receive(self) -> u16 {
        self.receive
    }

    pub fn from_path_mtu(mtu: u16, version: IpVersion) -> io::Result<Self> {
        let overhead = match version {
            IpVersion::V4 => 28,
            IpVersion::V6 => 48,
        };
        let payload = mtu
            .checked_sub(overhead)
            .filter(|value| *value > 0)
            .ok_or_else(invalid)?;
        Ok(Self::new(payload, payload))
    }

    pub fn intersect(self, other: Self) -> Self {
        Self::new(
            self.transmit.min(other.transmit),
            self.receive.min(other.receive),
        )
    }

    pub fn subtract_overhead(self, transmit: usize, receive: usize) -> Self {
        Self::new(
            usize::from(self.transmit).saturating_sub(transmit) as u16,
            usize::from(self.receive).saturating_sub(receive) as u16,
        )
    }

    pub fn quic_payload_limit(self) -> io::Result<u16> {
        let payload = self.transmit.min(self.receive);
        if payload < QUIC_MIN_PAYLOAD_BYTES {
            return Err(invalid());
        }
        Ok(payload)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "datagram path budget is insufficient",
    )
}

/// Enforce the caller's limit outside a codec, and retain all lower-layer caps.
pub(crate) fn bounded(
    inner: Box<dyn DatagramTransport>,
    budget: DatagramBudget,
) -> Box<dyn DatagramTransport> {
    Box::new(Bounded {
        inner,
        budget,
        closing: false,
        closed: false,
        observation: Some(crate::resources::observation::track(
            crate::resources::observation::ResourceKind::Association,
        )),
    })
}

struct Bounded {
    inner: Box<dyn DatagramTransport>,
    budget: DatagramBudget,
    closing: bool,
    closed: bool,
    observation: Option<crate::resources::observation::Guard>,
}

#[async_trait::async_trait]
impl DatagramTransport for Bounded {
    #[cfg(all(
        target_os = "linux",
        any(feature = "outbound-tuic", feature = "quinn-h3-transport")
    ))]
    async fn lease_quic_socket(
        &mut self,
        peer: std::net::SocketAddr,
    ) -> Result<Option<crate::transport::quic::PhysicalQuicLease>, DispatchError> {
        if self.closing {
            return Err(DispatchError::NotAllowed);
        }
        self.inner.lease_quic_socket(peer).await
    }

    fn supports_shared_destinations(&self) -> bool {
        self.inner.supports_shared_destinations()
    }

    fn supports_poll_receive(&self) -> bool {
        self.inner.supports_poll_receive()
    }

    fn poll_receive(
        &mut self,
        context: &mut std::task::Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> std::task::Poll<Result<Datagram, DispatchError>> {
        if self.closing {
            return std::task::Poll::Ready(Err(DispatchError::NotAllowed));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            let datagram = match self.inner.poll_receive(context, scratch) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(result) => match result {
                    Ok(datagram) => datagram,
                    Err(error) => return std::task::Poll::Ready(Err(error)),
                },
            };
            if datagram.payload.len()
                <= usize::from(self.payload_budget(&datagram.remote).receive())
            {
                return std::task::Poll::Ready(Ok(datagram));
            }
        }
        context.waker().wake_by_ref();
        std::task::Poll::Pending
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.budget.intersect(self.inner.payload_budget(peer))
    }
    fn send_owned(&mut self, datagram: Datagram) -> Result<super::OwnedDatagramSend, Datagram> {
        if self.closing
            || datagram.payload.len()
                > usize::from(self.payload_budget(&datagram.remote).transmit())
        {
            return Err(datagram);
        }
        self.inner.send_owned(datagram)
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closing {
            return Err(DispatchError::NotAllowed);
        }
        if datagram.payload.len() > usize::from(self.payload_budget(&datagram.remote).transmit()) {
            return Err(invalid().into());
        }
        self.inner.send(datagram).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closing {
            return Err(DispatchError::NotAllowed);
        }
        loop {
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                let datagram = self.inner.receive().await?;
                if datagram.payload.len()
                    <= usize::from(self.payload_budget(&datagram.remote).receive())
                {
                    return Ok(datagram);
                }
            }
            tokio::task::yield_now().await;
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        if self.closed {
            return Ok(());
        }
        self.closing = true;
        self.inner.close().await?;
        self.closed = true;
        self.observation.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::task::{ArcWake, waker};
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    struct PolledPackets {
        packets: VecDeque<Datagram>,
        polls: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl DatagramTransport for PolledPackets {
        fn supports_shared_destinations(&self) -> bool {
            true
        }
        fn payload_budget(&self, _peer: &Destination) -> DatagramBudget {
            DatagramBudget::new(2, 3)
        }
        fn supports_poll_receive(&self) -> bool {
            true
        }
        fn poll_receive(
            &mut self,
            _context: &mut Context<'_>,
            _scratch: &mut Vec<u8>,
        ) -> Poll<Result<Datagram, DispatchError>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            match self.packets.pop_front() {
                Some(datagram) => Poll::Ready(Ok(datagram)),
                None => Poll::Pending,
            }
        }
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            panic!("polled test must not use asynchronous receive")
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn packet(payload: &'static [u8]) -> Datagram {
        Datagram {
            remote: Destination::Ip("198.51.100.1:443".parse().unwrap()),
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }

    struct OwnedPackets(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl DatagramTransport for OwnedPackets {
        fn send_owned(&mut self, _: Datagram) -> Result<super::super::OwnedDatagramSend, Datagram> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(Box::pin(async { Ok(()) }))
        }
        async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
            panic!("bounded owned path must not invoke legacy send")
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }
    #[tokio::test]
    async fn polled_datagram_bounded_owned_send_preserves_budget_and_close() {
        let sends = Arc::new(AtomicUsize::new(0));
        let mut transport = bounded(
            Box::new(OwnedPackets(sends.clone())),
            DatagramBudget::new(3, 3),
        );
        let Err(oversized) = transport.send_owned(packet(b"four")) else {
            panic!("oversized packet reached inner transport")
        };
        assert_eq!(oversized.payload, b"four"[..]);
        assert_eq!(sends.load(Ordering::Relaxed), 0);
        transport.send_owned(packet(b"ok!")).unwrap().await.unwrap();
        assert_eq!(sends.load(Ordering::Relaxed), 1);
        transport.close().await.unwrap();
        assert!(transport.send_owned(packet(b"ok!")).is_err());
        assert_eq!(sends.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn polled_datagram_bounded_filters_complete_packets_and_blocks_after_close() {
        let polls = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));
        let mut transport = bounded(
            Box::new(PolledPackets {
                packets: [packet(b"oversized"), packet(b"four"), packet(b"ok!")].into(),
                polls: polls.clone(),
                closes: closes.clone(),
            }),
            DatagramBudget::new(10, 4),
        );
        assert!(transport.supports_poll_receive());
        assert!(transport.supports_shared_destinations());
        assert_eq!(
            transport.payload_budget(&packet(b"").remote),
            DatagramBudget::new(2, 3)
        );
        let parent = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&parent);
        let mut scratch = Vec::new();
        let Poll::Ready(Ok(datagram)) = transport.poll_receive(&mut context, &mut scratch) else {
            panic!("valid packet must follow dropped oversized packets")
        };
        assert_eq!(datagram.payload, Bytes::from_static(b"ok!"));
        assert_eq!(polls.load(Ordering::Relaxed), 3);
        transport.close().await.unwrap();
        transport.close().await.unwrap();
        assert_eq!(closes.load(Ordering::Relaxed), 1);
        assert!(matches!(
            transport.poll_receive(&mut context, &mut scratch),
            Poll::Ready(Err(DispatchError::NotAllowed))
        ));
        assert_eq!(polls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn polled_datagram_bounded_yields_and_wakes_after_oversized_packet_budget() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut packets = VecDeque::new();
        for _ in 0..=crate::limits::IO_POLL_BUDGET {
            packets.push_back(packet(b"four"));
        }
        packets.push_back(packet(b"ok!"));
        let mut transport = bounded(
            Box::new(PolledPackets {
                packets,
                polls: polls.clone(),
                closes: Arc::default(),
            }),
            DatagramBudget::new(10, 4),
        );
        let wakes = Arc::new(WakeCount::default());
        let parent = waker(wakes.clone());
        let mut context = Context::from_waker(&parent);
        let mut scratch = Vec::new();
        assert!(
            transport
                .poll_receive(&mut context, &mut scratch)
                .is_pending()
        );
        assert_eq!(polls.load(Ordering::Relaxed), crate::limits::IO_POLL_BUDGET);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        let Poll::Ready(Ok(datagram)) = transport.poll_receive(&mut context, &mut scratch) else {
            panic!("next poll must consume the remaining oversized packet and valid packet")
        };
        assert_eq!(datagram.payload, Bytes::from_static(b"ok!"));
        assert_eq!(
            polls.load(Ordering::Relaxed),
            crate::limits::IO_POLL_BUDGET + 2
        );
    }
}
