//! Public Gecko framing over the existing Salamander transport. QUIC remains
//! the authentication layer. Reassembly is local to one immutable peer.
use crate::{
    config::Hysteria2Gecko,
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
const HEADER: usize = 5;
const PENDING: usize = 8;
const TTL: Duration = Duration::from_secs(8);
struct Entry {
    id: u8,
    total: u8,
    chunks: [Option<Bytes>; 8],
    bytes: usize,
    deadline: Instant,
}
struct Gecko {
    inner: Box<dyn DatagramTransport>,
    options: Hysteria2Gecko,
    peer: Destination,
    limit: u16,
    next: u8,
    pending: Vec<Entry>,
    closed: bool,
}
pub(super) fn wrap(
    inner: Box<dyn DatagramTransport>,
    options: Hysteria2Gecko,
    peer: Destination,
    limit: u16,
) -> Box<dyn DatagramTransport> {
    Box::new(Gecko {
        inner: super::salamander::wrap(inner, &options.password),
        options,
        peer,
        limit,
        next: rand::random(),
        pending: Vec::new(),
        closed: false,
    })
}
fn invalid() -> DispatchError {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Gecko packet boundary").into()
}
impl Gecko {
    fn accept(&mut self, mut packet: Datagram) -> Option<Datagram> {
        let now = Instant::now();
        self.pending.retain(|entry| entry.deadline > now);
        if self.closed
            || packet.remote != self.peer
            || packet.payload.is_empty()
            || packet.payload.len()
                > usize::from(self.inner.payload_budget(&packet.remote).receive())
        {
            return None;
        }
        if packet.payload[0] & 0x80 == 0 {
            return (packet.payload.len() <= usize::from(self.limit)).then_some(packet);
        }
        let b = &packet.payload;
        if b.len() < HEADER {
            return None;
        }
        let (id, index, total) = (b[1], b[2] >> 4, b[2] & 15);
        let start = HEADER + usize::from(u16::from_be_bytes([b[3], b[4]]));
        if !(2..=8).contains(&total) || index >= total || start > b.len() {
            return None;
        }
        let chunk = &b[start..];
        if chunk.len() > usize::from(self.limit) {
            return None;
        }
        let pos = if let Some(pos) = self.pending.iter().position(|entry| entry.id == id) {
            pos
        } else {
            if self.pending.len() == PENDING {
                let pos = self
                    .pending
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.deadline)
                    .unwrap()
                    .0;
                self.pending.swap_remove(pos);
            }
            self.pending.push(Entry {
                id,
                total,
                chunks: std::array::from_fn(|_| None),
                bytes: 0,
                deadline: now + TTL,
            });
            self.pending.len() - 1
        };
        let entry = &mut self.pending[pos];
        if entry.total != total || entry.chunks[usize::from(index)].is_some() {
            return None;
        }
        if entry.bytes + chunk.len() > usize::from(self.limit) {
            self.pending.swap_remove(pos);
            return None;
        }
        // Copy the validated chunk so random padding does not remain retained.
        entry.chunks[usize::from(index)] = Some(Bytes::copy_from_slice(chunk));
        entry.bytes += chunk.len();
        if !entry.chunks[..usize::from(total)]
            .iter()
            .all(Option::is_some)
        {
            return None;
        }
        let entry = self.pending.swap_remove(pos);
        let mut payload = Vec::with_capacity(entry.bytes);
        for bytes in entry.chunks.into_iter().take(usize::from(total)) {
            payload.extend_from_slice(&bytes.unwrap());
        }
        if payload.first().is_none_or(|byte| byte & 0x80 == 0) {
            return None;
        }
        packet.payload = payload.into();
        Some(packet)
    }
}
#[async_trait]
impl DatagramTransport for Gecko {
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.inner
            .payload_budget(peer)
            .intersect(DatagramBudget::new(self.limit, self.limit))
    }
    fn supports_poll_receive(&self) -> bool {
        self.inner.supports_poll_receive()
    }
    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        if self.closed {
            return Poll::Ready(Err(invalid()));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            let packet = std::task::ready!(self.inner.poll_receive(cx, scratch))?;
            if let Some(packet) = self.accept(packet) {
                return Poll::Ready(Ok(packet));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn send_owned(
        &mut self,
        packet: Datagram,
    ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
        if self.closed
            || packet.remote != self.peer
            || packet.payload.is_empty()
            || packet.payload[0] & 0x80 != 0
            || packet.payload.len() > usize::from(self.payload_budget(&packet.remote).transmit())
        {
            return Err(packet);
        }
        self.inner.send_owned(packet)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if self.closed
            || packet.remote != self.peer
            || packet.payload.is_empty()
            || packet.payload.len() > usize::from(self.payload_budget(&packet.remote).transmit())
        {
            return Err(invalid());
        }
        if packet.payload[0] & 0x80 == 0 {
            return self.inner.send(packet).await;
        }
        // max-packet-size controls padding, as in the reference. A small
        // configured maximum cannot reduce the mandatory header/chunk length.
        let wire = usize::from(self.inner.payload_budget(&packet.remote).transmit());
        let capacity = wire
            .checked_sub(HEADER)
            .filter(|n| *n > 0)
            .ok_or_else(invalid)?;
        let choices: Vec<_> = (2..=8)
            .filter(|count| {
                packet.payload.len() - (count - 1) * (packet.payload.len() / count) <= capacity
            })
            .collect();
        if choices.is_empty() {
            return Err(invalid());
        }
        let count = choices[rand::random_range(0..choices.len())];
        let chunk = packet.payload.len() / count;
        self.next = self.next.wrapping_add(1);
        let id = self.next;
        for index in 0..count {
            let start = index * chunk;
            let end = if index + 1 == count {
                packet.payload.len()
            } else {
                start + chunk
            };
            let bytes = &packet.payload[start..end];
            let base = usize::from(super::salamander::OVERHEAD) + HEADER + bytes.len();
            let high = usize::from(self.options.max_packet_size)
                .min(wire + usize::from(super::salamander::OVERHEAD));
            let low = usize::from(self.options.min_packet_size).max(base);
            let padding = if low > high {
                0
            } else {
                rand::random_range(low..=high) - base
            };
            let mut frame = vec![0u8; HEADER + padding + bytes.len()];
            frame[0] = 0x80;
            frame[1] = id;
            frame[2] = ((index as u8) << 4) | (count as u8);
            frame[3..5].copy_from_slice(&(padding as u16).to_be_bytes());
            rand::fill(&mut frame[HEADER..HEADER + padding]);
            frame[HEADER + padding..].copy_from_slice(bytes);
            self.inner
                .send(Datagram {
                    remote: packet.remote.clone(),
                    payload: frame.into(),
                    sniffed_domain: None,
                })
                .await?;
        }
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closed {
            return Err(invalid());
        }
        loop {
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                let packet = self.inner.receive().await?;
                if let Some(packet) = self.accept(packet) {
                    return Ok(packet);
                }
            }
            tokio::task::yield_now().await;
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.pending.clear();
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::mpsc;
    struct Packets {
        send: mpsc::Sender<Datagram>,
        receive: mpsc::Receiver<Datagram>,
        closed: Arc<AtomicBool>,
    }
    #[async_trait]
    impl DatagramTransport for Packets {
        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            DatagramBudget::new(2048, 2048)
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            self.send.send(packet).await.map_err(|_| invalid())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.receive.recv().await.ok_or_else(invalid)
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }
    fn setup() -> (
        Gecko,
        mpsc::Receiver<Datagram>,
        mpsc::Sender<Datagram>,
        Arc<AtomicBool>,
    ) {
        let (send, sent) = mpsc::channel(16);
        let (reply, receive) = mpsc::channel(16);
        let closed = Arc::new(AtomicBool::new(false));
        let options = Hysteria2Gecko {
            password: "wire fixture".into(),
            min_packet_size: 512,
            max_packet_size: 1200,
        };
        (
            Gecko {
                inner: super::super::salamander::wrap(
                    Box::new(Packets {
                        send,
                        receive,
                        closed: closed.clone(),
                    }),
                    &options.password,
                ),
                options,
                peer: Destination::Ip("192.0.2.1:443".parse().unwrap()),
                limit: 1400,
                next: 0,
                pending: Vec::new(),
                closed: false,
            },
            sent,
            reply,
            closed,
        )
    }
    #[tokio::test]
    async fn gecko_memory_wire_reassembles_reordered_long_headers_and_preserves_short_headers() {
        let (mut gecko, mut sent, reply, closed) = setup();
        let mut plain = vec![7; 1400];
        plain[0] = 0xc0;
        gecko
            .send(Datagram {
                remote: gecko.peer.clone(),
                payload: plain.clone().into(),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        let mut fragments = Vec::new();
        while let Ok(packet) = sent.try_recv() {
            assert!((512..=1200).contains(&packet.payload.len()));
            fragments.push(packet);
        }
        assert!((2..=8).contains(&fragments.len()));
        let mut wrong = fragments[0].clone();
        wrong.remote = Destination::Ip("192.0.2.2:443".parse().unwrap());
        reply.send(wrong).await.unwrap();
        for fragment in fragments.into_iter().rev() {
            reply.send(fragment).await.unwrap();
        }
        assert_eq!(gecko.receive().await.unwrap().payload, plain);
        let short = Bytes::from_static(&[0x40, 1, 2, 3]);
        gecko
            .send(Datagram {
                remote: gecko.peer.clone(),
                payload: short.clone(),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        let packet = sent.recv().await.unwrap();
        assert_eq!(packet.payload.len(), short.len() + 8);
        reply.send(packet).await.unwrap();
        assert_eq!(gecko.receive().await.unwrap().payload, short);
        gecko.close().await.unwrap();
        assert!(closed.load(Ordering::Acquire));
        assert!(gecko.receive().await.is_err());
        assert!(
            gecko
                .send(Datagram {
                    remote: gecko.peer.clone(),
                    payload: Bytes::from_static(&[0x40]),
                    sniffed_domain: None
                })
                .await
                .is_err()
        );
    }
    #[tokio::test(start_paused = true)]
    async fn gecko_memory_slow_partial_input_and_expiry_have_local_bounds() {
        let (mut gecko, _, _, _) = setup();
        for id in 0..32 {
            let mut frame = vec![0x80, id, 2, 0, 0];
            frame.extend_from_slice(&[1; 700]);
            assert!(
                gecko
                    .accept(Datagram {
                        remote: gecko.peer.clone(),
                        payload: frame.into(),
                        sniffed_domain: None
                    })
                    .is_none()
            );
            assert!(gecko.pending.len() <= 8);
            assert!(gecko.pending.iter().map(|entry| entry.bytes).sum::<usize>() <= 8 * 1400);
        }
        tokio::time::advance(TTL + Duration::from_secs(1)).await;
        let _ = gecko.accept(Datagram {
            remote: gecko.peer.clone(),
            payload: Bytes::from_static(&[0x40]),
            sniffed_domain: None,
        });
        assert!(gecko.pending.is_empty());
    }
}
