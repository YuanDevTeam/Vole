//! Length-delimited VLESS UDP and packetaddr. XUDP uses the shared mux codec.
use super::{VlessCommand, outbound::PreparedStream};
use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::{
        DEFAULT_ESTABLISH_TIMEOUT,
        address::{decode_packet_addr, encode_packet_addr},
    },
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

pub(super) struct VlessDatagram {
    io: Option<BoxStream>,
    pending_write: Option<PendingWrite>,
    pending: Option<PreparedStream>,
    packet_addr: bool,
    peer: Option<Destination>,
    initialized: bool,
    deadline: Instant,
    resolution: ResolutionContext,
    budget: DatagramBudget,
    input: BytesMut,
    cancellation: tokio_util::sync::CancellationToken,
}

struct PendingWrite {
    wire: Bytes,
    offset: usize,
}

impl VlessDatagram {
    pub(super) fn new(
        prepared: PreparedStream,
        budget: DatagramBudget,
        resolution: ResolutionContext,
    ) -> Self {
        let deadline = prepared.deadline;
        let cancellation = prepared.token.clone();
        Self {
            io: None,
            pending_write: None,
            pending: Some(prepared),
            packet_addr: false,
            peer: None,
            initialized: false,
            deadline,
            resolution,
            budget,
            input: BytesMut::new(),
            cancellation,
        }
    }
    pub(super) async fn packet_addr(
        prepared: PreparedStream,
        budget: DatagramBudget,
        resolution: ResolutionContext,
    ) -> Result<Self, DispatchError> {
        let deadline = prepared.deadline;
        let cancellation = prepared.token.clone();
        // This protocol destination is fixed before the first business packet.
        // Finish transport setup before publishing a shared association, so a
        // cancelled send can never consume and drop its PreparedStream owner.
        let target = Destination::domain("sp.packet-addr.v2fly.arpa", 443)?;
        let io = prepared.finish(VlessCommand::Udp, Some(&target)).await?;
        Ok(Self {
            io: Some(io),
            pending_write: None,
            pending: None,
            packet_addr: true,
            peer: None,
            initialized: false,
            deadline,
            resolution,
            budget,
            input: BytesMut::new(),
            cancellation,
        })
    }

    async fn flush_packet_addr_pending(&mut self) -> io::Result<()> {
        if self.pending_write.is_none() {
            return Ok(());
        }
        let first = !self.initialized;
        let deadline = self.deadline;
        if first && Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let cancellation = self.cancellation.clone();
        // Keep both the stream and each successful write's offset in self.
        // A cancelled send/receive resumes this exact frame before any new one.
        let write = async {
            let pending = self
                .pending_write
                .as_mut()
                .expect("pending packetaddr frame");
            let io = self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
            while pending.offset < pending.wire.len() {
                let written = io.write(&pending.wire[pending.offset..]).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                pending.offset += written;
            }
            io.flush().await
        };
        tokio::select! { biased;
            () = cancellation.cancelled() => return Err(io::ErrorKind::ConnectionAborted.into()),
            result = async {
                if first {
                    tokio::time::timeout_at(deadline, write)
                        .await.map_err(|_| io::ErrorKind::TimedOut)?
                } else {
                    write.await
                }
            } => result?,
        }
        self.pending_write = None;
        self.initialized = true;
        Ok(())
    }

    async fn send_packet_addr(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        let result = async {
            self.flush_packet_addr_pending().await?;
            let deadline = if self.initialized {
                Instant::now() + DEFAULT_ESTABLISH_TIMEOUT
            } else {
                self.deadline
            };
            let peer = tokio::select! { biased;
                () = self.cancellation.cancelled() => return Err(DispatchError::NotAllowed),
                peer = self.resolution.resolve_ip(&packet.remote, deadline) => peer?,
            };
            let mut wire = BytesMut::with_capacity(packet.payload.len() + 21);
            wire.put_u16(0);
            encode_packet_addr(&peer.into(), &mut wire)?;
            wire.extend_from_slice(&packet.payload);
            let length = (wire.len() - 2) as u16;
            wire[..2].copy_from_slice(&length.to_be_bytes());
            self.pending_write = Some(PendingWrite {
                wire: wire.freeze(),
                offset: 0,
            });
            self.flush_packet_addr_pending().await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.close().await?;
        }
        result
    }

    async fn fill(&mut self, required: usize) -> io::Result<()> {
        if required > crate::limits::VLESS_UDP_FRAME_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut scratch = [0; 1024];
        while self.input.len() < required {
            let size = (required - self.input.len()).min(scratch.len());
            let count = self
                .io
                .as_mut()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .read(&mut scratch[..size])
                .await?;
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.input.extend_from_slice(&scratch[..count]);
        }
        Ok(())
    }
    async fn next(&mut self) -> io::Result<(Destination, Bytes)> {
        self.fill(2).await?;
        let length = u16::from_be_bytes(self.input[..2].try_into().unwrap()) as usize;
        if length == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.fill(length + 2).await?;
        let packet = self.input.split().freeze().slice(2..);
        let (peer, start) = if self.packet_addr {
            decode_packet_addr(&packet)?
        } else {
            (self.peer.clone().ok_or(io::ErrorKind::InvalidData)?, 0)
        };
        if start == packet.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok((peer, packet.slice(start..)))
    }
}

#[async_trait]
impl DatagramTransport for VlessDatagram {
    fn supports_shared_destinations(&self) -> bool {
        self.packet_addr
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        let overhead = if !self.packet_addr {
            0
        } else if matches!(peer,Destination::Ip(addr) if addr.is_ipv4()) {
            7
        } else {
            19
        };
        let max = u16::MAX - overhead;
        self.budget.intersect(DatagramBudget::new(max, max))
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if self.cancellation.is_cancelled() {
            self.close().await?;
            return Err(DispatchError::NotAllowed);
        }
        if self.io.is_none() && self.pending.is_none() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        if packet.payload.is_empty()
            || packet.remote.port() == 0
            || packet.payload.len() > self.payload_budget(&packet.remote).transmit() as usize
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        if self.packet_addr {
            return self.send_packet_addr(packet).await;
        }
        if self
            .peer
            .as_ref()
            .is_some_and(|peer| *peer != packet.remote)
        {
            return Err(DispatchError::NotAllowed);
        }
        let first = !self.initialized;
        if first && Instant::now() >= self.deadline {
            self.io.take();
            self.pending.take();
            return Err(DispatchError::TimedOut);
        }
        let mut wire = BytesMut::with_capacity(packet.payload.len() + 21);
        wire.put_u16(0);
        wire.extend_from_slice(&packet.payload);
        let length = (wire.len() - 2) as u16;
        wire[..2].copy_from_slice(&length.to_be_bytes());
        let mut stream = if let Some(prepared) = self.pending.take() {
            prepared
                .finish(VlessCommand::Udp, Some(&packet.remote))
                .await?
        } else {
            self.io
                .take()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
        };
        let write = async {
            stream.write_all(&wire).await?;
            stream.flush().await
        };
        if first {
            tokio::time::timeout_at(self.deadline, write)
                .await
                .map_err(|_| DispatchError::TimedOut)??;
        } else {
            write.await?;
        }
        self.peer.get_or_insert(packet.remote);
        self.initialized = true;
        self.io = Some(stream);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.io.is_none() && self.pending.is_none() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        if self.packet_addr
            && let Err(error) = self.flush_packet_addr_pending().await
        {
            self.close().await?;
            return Err(error.into());
        }
        if !self.initialized {
            self.cancellation.cancelled().await;
            self.close().await?;
            return Err(DispatchError::NotAllowed);
        }
        let mut count = 0;
        loop {
            let (remote, payload) = match self.next().await {
                Ok(packet) => packet,
                Err(error) => {
                    self.io.take();
                    return Err(error.into());
                }
            };
            if payload.len() <= self.payload_budget(&remote).receive() as usize {
                return Ok(Datagram {
                    remote,
                    payload,
                    sniffed_domain: None,
                });
            }
            count += 1;
            if count == crate::limits::IO_POLL_BUDGET {
                tokio::task::yield_now().await;
                count = 0;
            }
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.io.take();
        self.pending.take();
        self.pending_write = None;
        self.input.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    #[derive(Clone)]
    struct Gates {
        write_bytes: Arc<AtomicUsize>,
        flushes: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl Gates {
        fn release(&self) {
            self.write_bytes.store(usize::MAX, Ordering::SeqCst);
            self.flushes.store(usize::MAX, Ordering::SeqCst);
        }
    }
    struct GatedIo {
        raw: DuplexStream,
        gates: Gates,
    }
    impl Drop for GatedIo {
        fn drop(&mut self) {
            self.gates.drops.fetch_add(1, Ordering::SeqCst);
        }
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
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let available = self.gates.write_bytes.load(Ordering::SeqCst);
            if available == 0 {
                return Poll::Pending;
            }
            let size = data.len().min(available);
            let result = Pin::new(&mut self.raw).poll_write(cx, &data[..size]);
            if let Poll::Ready(Ok(written)) = result
                && available != usize::MAX
            {
                self.gates.write_bytes.fetch_sub(written, Ordering::SeqCst);
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let available = self.gates.flushes.load(Ordering::SeqCst);
            if available == 0 {
                return Poll::Pending;
            }
            let result = Pin::new(&mut self.raw).poll_flush(cx);
            if matches!(result, Poll::Ready(Ok(()))) && available != usize::MAX {
                self.gates.flushes.fetch_sub(1, Ordering::SeqCst);
            }
            result
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }
    async fn fixture(packet_addr: bool) -> (VlessDatagram, DuplexStream, Gates) {
        let (raw, peer) = tokio::io::duplex(4096);
        let gates = Gates {
            write_bytes: Arc::new(AtomicUsize::new(usize::MAX)),
            flushes: Arc::new(AtomicUsize::new(usize::MAX)),
            drops: Arc::default(),
        };
        let prepared = PreparedStream::for_memory_test(
            Box::new(GatedIo {
                raw,
                gates: gates.clone(),
            }),
            Instant::now() + Duration::from_secs(5),
            tokio_util::sync::CancellationToken::new(),
        );
        let budget = DatagramBudget::new(1452, 1452);
        let resolution = ResolutionContext::default();
        let transport = if packet_addr {
            VlessDatagram::packet_addr(prepared, budget, resolution)
                .await
                .unwrap()
        } else {
            VlessDatagram::new(prepared, budget, resolution)
        };
        (transport, peer, gates)
    }
    fn packet(remote: &str, payload: &'static [u8]) -> Datagram {
        Datagram {
            remote: remote.parse::<std::net::SocketAddr>().unwrap().into(),
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }
    fn header(remote: &Destination) -> Vec<u8> {
        super::super::codec::encode_header(
            uuid::Uuid::from_bytes([7; 16]),
            VlessCommand::Udp,
            Some(remote),
            false,
        )
        .unwrap()
        .to_vec()
    }
    fn magic_header() -> Vec<u8> {
        header(&Destination::domain("sp.packet-addr.v2fly.arpa", 443).unwrap())
    }
    fn wire(packet: &Datagram) -> Vec<u8> {
        let mut output = BytesMut::new();
        output.put_u16(0);
        encode_packet_addr(&packet.remote, &mut output).unwrap();
        output.extend_from_slice(&packet.payload);
        let length = (output.len() - 2) as u16;
        output[..2].copy_from_slice(&length.to_be_bytes());
        output.to_vec()
    }

    #[tokio::test]
    async fn packetaddr_shares_one_magic_request_and_preserves_response_sources() {
        let (mut transport, mut peer, _) = fixture(true).await;
        assert!(transport.supports_shared_destinations());
        let first = packet("192.0.2.1:53", b"first");
        let second = packet("[2001:db8::2]:54", b"second");
        transport.send(first.clone()).await.unwrap();
        transport.send(second.clone()).await.unwrap();
        let mut expected = magic_header();
        expected.extend(wire(&first));
        expected.extend(wire(&second));
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected, "the magic VLESS request must occur once");
        let mut responses = vec![0, 0];
        responses.extend(wire(&second));
        responses.extend(wire(&first));
        peer.write_all(&responses).await.unwrap();
        for expected in [second, first] {
            let actual = transport.receive().await.unwrap();
            assert_eq!(actual.remote, expected.remote);
            assert_eq!(actual.payload, expected.payload);
        }
    }

    #[tokio::test]
    async fn raw_remains_lazy_fixed_target_and_closes_after_partial_send_cancel() {
        let (mut transport, mut peer, gates) = fixture(false).await;
        assert!(!transport.supports_shared_destinations());
        assert!(transport.io.is_none() && transport.pending.is_some());
        let first = packet("192.0.2.1:53", b"first");
        let second = packet("198.51.100.1:54", b"second");
        transport.send(first.clone()).await.unwrap();
        assert!(matches!(
            transport.send(second).await,
            Err(DispatchError::NotAllowed)
        ));
        let mut expected = header(&first.remote);
        expected.extend_from_slice(&(first.payload.len() as u16).to_be_bytes());
        expected.extend_from_slice(&first.payload);
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        transport.close().await.unwrap();
        assert_eq!(gates.drops.load(Ordering::SeqCst), 1);

        let (mut raw, mut peer, gates) = fixture(false).await;
        gates.write_bytes.store(1, Ordering::SeqCst);
        assert!(futures_util::poll!(raw.send(first)).is_pending());
        assert!(raw.io.is_none() && raw.pending.is_none());
        let mut prefix = Vec::new();
        peer.read_to_end(&mut prefix).await.unwrap();
        assert_eq!(prefix.len(), 1);
        assert_eq!(gates.drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_packetaddr_header_payload_and_flush_resume_without_replay() {
        let first = packet("192.0.2.1:53", b"first");
        let second = packet("198.51.100.1:54", b"second");
        let header_len = magic_header().len();
        for (write_bytes, flushes) in [
            (1, usize::MAX),
            (header_len + 3, usize::MAX),
            (header_len + wire(&first).len() - 1, usize::MAX),
            (usize::MAX, 1),
        ] {
            for resume_receive in [false, true] {
                let (mut transport, mut peer, gates) = fixture(true).await;
                gates.write_bytes.store(write_bytes, Ordering::SeqCst);
                gates.flushes.store(flushes, Ordering::SeqCst);
                assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
                assert!(transport.io.is_some() && transport.pending_write.is_some());
                assert_eq!(gates.drops.load(Ordering::SeqCst), 0);
                gates.release();
                let mut expected = magic_header();
                expected.extend(wire(&first));
                if resume_receive {
                    let mut response = vec![0, 0];
                    response.extend(wire(&second));
                    peer.write_all(&response).await.unwrap();
                    let actual = transport.receive().await.unwrap();
                    assert_eq!(actual.remote, second.remote);
                    assert_eq!(actual.payload, second.payload);
                } else {
                    transport.send(second.clone()).await.unwrap();
                    expected.extend(wire(&second));
                }
                assert!(transport.pending_write.is_none());
                let mut actual = vec![0; expected.len()];
                peer.read_exact(&mut actual).await.unwrap();
                assert_eq!(
                    actual, expected,
                    "cancelled prefixes must occur exactly once"
                );
                transport.close().await.unwrap();
                assert_eq!(gates.drops.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_first_frame_keeps_deadline_and_established_frames_outlive_it() {
        let first = packet("192.0.2.1:53", b"first");
        let second = packet("198.51.100.1:54", b"second");
        let (mut transport, mut peer, gates) = fixture(true).await;
        gates.write_bytes.store(1, Ordering::SeqCst);
        assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
        tokio::time::advance(Duration::from_secs(6)).await;
        gates.release();
        assert!(matches!(
            transport.send(second.clone()).await,
            Err(DispatchError::TimedOut)
        ));
        assert!(transport.io.is_none() && transport.pending_write.is_none());
        let mut prefix = Vec::new();
        peer.read_to_end(&mut prefix).await.unwrap();
        assert_eq!(prefix, magic_header()[..1]);
        assert_eq!(gates.drops.load(Ordering::SeqCst), 1);

        let (mut established, mut peer, _) = fixture(true).await;
        established.send(first.clone()).await.unwrap();
        tokio::time::advance(Duration::from_secs(6)).await;
        established.send(second.clone()).await.unwrap();
        let mut expected = magic_header();
        expected.extend(wire(&first));
        expected.extend(wire(&second));
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn close_and_stop_discard_pending_frame_and_release_the_only_stream() {
        for stop in [false, true] {
            let (mut transport, mut peer, gates) = fixture(true).await;
            gates
                .write_bytes
                .store(magic_header().len() + 3, Ordering::SeqCst);
            let first = packet("192.0.2.1:53", b"first");
            assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
            if stop {
                transport.cancellation.cancel();
                assert!(transport.receive().await.is_err());
            } else {
                transport.close().await.unwrap();
            }
            assert!(transport.io.is_none() && transport.pending_write.is_none());
            assert_eq!(gates.drops.load(Ordering::SeqCst), 1);
            assert!(transport.send(first.clone()).await.is_err());
            let mut actual = Vec::new();
            peer.read_to_end(&mut actual).await.unwrap();
            let mut expected = magic_header();
            expected.extend_from_slice(&wire(&first)[..3]);
            assert_eq!(
                actual, expected,
                "close must not append to an unfinished frame"
            );
            assert_eq!(gates.drops.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn fragmented_response_keeps_parser_progress_after_cancellation() {
        let first = packet("192.0.2.1:53", b"first");
        let second = packet("198.51.100.1:54", b"second");
        let mut response = vec![0, 0];
        response.extend(wire(&second));
        for split in [1, 3, response.len() - 1] {
            let (mut transport, mut peer, _) = fixture(true).await;
            transport.send(first.clone()).await.unwrap();
            peer.write_all(&response[..split]).await.unwrap();
            assert!(futures_util::poll!(transport.receive()).is_pending());
            peer.write_all(&response[split..]).await.unwrap();
            let actual = transport.receive().await.unwrap();
            assert_eq!(actual.remote, second.remote);
            assert_eq!(actual.payload, second.payload);
        }
    }
}
