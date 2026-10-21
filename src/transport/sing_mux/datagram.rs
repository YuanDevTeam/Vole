//! Address-per-packet sing-mux UDP. Partial reads and one pending write survive
//! cancellation so literal destinations can share one source-owned wire.
use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::BytesMut;
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub(crate) struct DatagramIo {
    io: Option<BoxStream>,
    input: BytesMut,
    budget: DatagramBudget,
    resolution: ResolutionContext,
    deadline: Instant,
    first: bool,
    pending_write: Option<PendingWrite>,
    cancel: CancellationToken,
}
struct PendingWrite {
    wire: Vec<u8>,
    offset: usize,
}
impl DatagramIo {
    pub(crate) fn new(
        io: BoxStream,
        budget: DatagramBudget,
        resolution: ResolutionContext,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            io: Some(io),
            input: BytesMut::new(),
            budget,
            resolution,
            deadline,
            first: true,
            pending_write: None,
            cancel,
        }
    }
    // A cancelled logical target may already have submitted a frame prefix.
    // Finish exactly that retained frame before the next send or receive;
    // never duplicate bytes or add a per-target payload queue.
    async fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending_write.is_none() {
            return Ok(());
        }
        if self.first && Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let first = self.first;
        let deadline = self.deadline;
        let cancel = self.cancel.clone();
        let write = async {
            let pending = self.pending_write.as_mut().expect("pending sing-mux frame");
            let io = self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
            while pending.offset < pending.wire.len() {
                let written = io.write(&pending.wire[pending.offset..]).await?;
                if written == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                pending.offset += written;
            }
            io.flush().await
        };
        tokio::select! { biased;
            ()=cancel.cancelled()=>return Err(io::ErrorKind::ConnectionAborted.into()),
            result=async {
                if first {
                    tokio::time::timeout_at(deadline, write)
                        .await.map_err(|_| io::ErrorKind::TimedOut)?
                } else {
                    write.await
                }
            }=>result?,
        }
        self.first = false;
        self.pending_write = None;
        Ok(())
    }
    async fn fill(&mut self, length: usize) -> io::Result<()> {
        if length > u16::MAX as usize + 261 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut scratch = [0; 1024];
        while self.input.len() < length {
            let count = (length - self.input.len()).min(scratch.len());
            let n = self
                .io
                .as_mut()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .read(&mut scratch[..count])
                .await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.input.extend_from_slice(&scratch[..n]);
        }
        Ok(())
    }
    async fn next(&mut self) -> io::Result<Datagram> {
        self.fill(2).await?;
        let address_len = match self.input[0] {
            1 => 7,
            4 => 19,
            3 => self.input[1] as usize + 4,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        self.fill(address_len + 2).await?;
        let (remote, _) = crate::socks5::decode_address(&self.input[..address_len])
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let length =
            u16::from_be_bytes(self.input[address_len..address_len + 2].try_into().unwrap())
                as usize;
        if length == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.fill(address_len + 2 + length).await?;
        let payload = self.input.split().freeze().slice(address_len + 2..);
        Ok(Datagram {
            remote,
            payload,
            sniffed_domain: None,
        })
    }
}
#[async_trait]
impl DatagramTransport for DatagramIo {
    fn supports_shared_destinations(&self) -> bool {
        true
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if packet.remote.port() == 0
            || packet.payload.is_empty()
            || packet.payload.len() > self.budget.transmit() as usize
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        if self.io.is_none() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        let result = async {
            self.flush_pending().await?;
            let deadline = if self.first {
                self.deadline
            } else {
                Instant::now() + crate::outbound::DEFAULT_ESTABLISH_TIMEOUT
            };
            let peer = tokio::select! { biased;
                ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
                peer=self.resolution.resolve_ip(&packet.remote,deadline)=>peer?,
            };
            let mut wire = Vec::with_capacity(packet.payload.len() + 21);
            crate::socks5::encode_address(&peer.into(), &mut wire)?;
            wire.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(&packet.payload);
            self.pending_write = Some(PendingWrite { wire, offset: 0 });
            self.flush_pending().await.map_err(DispatchError::from)
        }
        .await;
        if result.is_err() {
            self.close().await?;
        }
        result
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let cancel = self.cancel.clone();
        for count in 0_usize.. {
            let result = tokio::select! {biased;
                ()=cancel.cancelled()=>Err(io::ErrorKind::ConnectionAborted.into()),
                result=async {self.flush_pending().await?;self.next().await}=>result,
            };
            match result {
                Ok(packet) if packet.payload.len() <= self.budget.receive() as usize => {
                    return Ok(packet);
                }
                Ok(_) => {}
                Err(error) => {
                    self.close().await?;
                    return Err(error.into());
                }
            }
            if count % crate::limits::IO_POLL_BUDGET == crate::limits::IO_POLL_BUDGET - 1 {
                tokio::task::yield_now().await;
            }
        }
        unreachable!()
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.io.take();
        self.pending_write = None;
        self.input.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    #[derive(Clone)]
    struct Gates {
        write_bytes: Arc<AtomicUsize>,
        flush_blocked: Arc<AtomicBool>,
    }
    impl Gates {
        fn release(&self) {
            self.write_bytes.store(usize::MAX, Ordering::SeqCst);
            self.flush_blocked.store(false, Ordering::SeqCst);
        }
    }
    struct GatedIo {
        raw: DuplexStream,
        gates: Gates,
    }
    impl AsyncRead for GatedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_read(cx, out)
        }
    }
    impl AsyncWrite for GatedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = self
                .gates
                .write_bytes
                .load(Ordering::SeqCst)
                .min(input.len());
            if count == 0 {
                return Poll::Pending;
            }
            let written =
                std::task::ready!(Pin::new(&mut self.raw).poll_write(cx, &input[..count]))?;
            self.gates.write_bytes.fetch_sub(written, Ordering::SeqCst);
            Poll::Ready(Ok(written))
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.gates.flush_blocked.load(Ordering::SeqCst) {
                Poll::Pending
            } else {
                Pin::new(&mut self.raw).poll_flush(cx)
            }
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }
    fn fixture(partial_write: bool) -> (DatagramIo, DuplexStream, Gates) {
        let (raw, peer) = tokio::io::duplex(4096);
        let gates = Gates {
            write_bytes: Arc::new(AtomicUsize::new(if partial_write { 3 } else { usize::MAX })),
            flush_blocked: Arc::new(AtomicBool::new(!partial_write)),
        };
        (
            DatagramIo::new(
                Box::new(GatedIo {
                    raw,
                    gates: gates.clone(),
                }),
                DatagramBudget::new(1452, 1452),
                ResolutionContext::default(),
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            ),
            peer,
            gates,
        )
    }
    fn packet(remote: &str, payload: &'static [u8]) -> Datagram {
        Datagram {
            remote: remote.parse::<std::net::SocketAddr>().unwrap().into(),
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }
    fn wire(packet: &Datagram) -> Vec<u8> {
        let mut bytes = Vec::new();
        crate::socks5::encode_address(&packet.remote, &mut bytes).unwrap();
        bytes.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&packet.payload);
        bytes
    }

    #[tokio::test]
    async fn cancelled_partial_write_and_flush_resume_before_send_or_receive() {
        for partial_write in [true, false] {
            for resume_receive in [true, false] {
                let (mut transport, mut peer, gates) = fixture(partial_write);
                assert!(transport.supports_shared_destinations());
                let first = packet("192.0.2.1:53", b"first");
                let second = packet("198.51.100.1:54", b"second");
                assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
                let pending = transport.pending_write.as_ref().unwrap();
                assert_eq!(
                    pending.offset,
                    if partial_write { 3 } else { wire(&first).len() }
                );
                assert_eq!(pending.wire, wire(&first));
                assert!(
                    transport.io.is_some(),
                    "cancel must retain the physical IO owner"
                );
                gates.release();
                let mut expected = wire(&first);
                if resume_receive {
                    peer.write_all(&wire(&second)).await.unwrap();
                    let response = transport.receive().await.unwrap();
                    assert_eq!(response.remote, second.remote);
                    assert_eq!(response.payload, second.payload);
                } else {
                    transport.send(second.clone()).await.unwrap();
                    expected.extend_from_slice(&wire(&second));
                }
                assert!(transport.pending_write.is_none());
                let mut actual = vec![0; expected.len()];
                peer.read_exact(&mut actual).await.unwrap();
                assert_eq!(
                    actual, expected,
                    "cancelled prefixes must not be duplicated"
                );
                transport.close().await.unwrap();
                assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_first_frame_keeps_its_deadline_but_established_frames_do_not() {
        let first = packet("192.0.2.1:53", b"first");
        let second = packet("198.51.100.1:54", b"second");
        let (mut transport, mut peer, gates) = fixture(true);
        assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
        tokio::time::advance(Duration::from_secs(6)).await;
        gates.release();
        assert!(matches!(
            transport.send(second.clone()).await,
            Err(DispatchError::TimedOut)
        ));
        assert!(transport.io.is_none());
        assert!(transport.pending_write.is_none());
        let mut actual = Vec::new();
        peer.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, wire(&first)[..3]);

        let (mut established, mut peer, gates) = fixture(false);
        gates.release();
        established.send(first.clone()).await.unwrap();
        tokio::time::advance(Duration::from_secs(6)).await;
        established.send(second.clone()).await.unwrap();
        let mut expected = wire(&first);
        expected.extend_from_slice(&wire(&second));
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        established.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_and_stop_discard_a_pending_frame_without_more_io() {
        for stop in [false, true] {
            let (mut transport, mut peer, _gates) = fixture(true);
            let first = packet("192.0.2.1:53", b"first");
            assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
            if stop {
                transport.cancel.cancel();
                assert!(transport.receive().await.is_err());
            } else {
                transport.close().await.unwrap();
            }
            transport.close().await.unwrap();
            assert!(transport.io.is_none());
            assert!(transport.pending_write.is_none());
            let mut actual = Vec::new();
            peer.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, wire(&first)[..3]);
            assert!(transport.send(first).await.is_err());
        }
    }
}
