//! Independent implementation of the public Salamander wire specification.
//! This is obfuscation, not authentication; QUIC authenticates decoded packets.
use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use blake2::{Blake2b256, Digest};
use bytes::Bytes;
use std::{io, sync::Arc};

pub(super) const OVERHEAD: u16 = 8;

pub(super) fn wrap(
    inner: Box<dyn DatagramTransport>,
    password: &str,
) -> Box<dyn DatagramTransport> {
    Box::new(Salamander {
        inner,
        password: Arc::from(password.as_bytes()),
    })
}
struct Salamander {
    inner: Box<dyn DatagramTransport>,
    password: Arc<[u8]>,
}

fn mask(password: &[u8], salt: &[u8], payload: &mut [u8]) {
    let mut hash = Blake2b256::new();
    hash.update(password);
    hash.update(salt);
    let key = hash.finalize();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % 32];
    }
}
fn encode(password: &[u8], salt: [u8; 8], payload: &[u8]) -> Bytes {
    let mut wire = Vec::with_capacity(payload.len() + usize::from(OVERHEAD));
    wire.extend_from_slice(&salt);
    wire.extend_from_slice(payload);
    mask(password, &salt, &mut wire[8..]);
    wire.into()
}
fn decode(password: &[u8], wire: Bytes) -> Option<Bytes> {
    if wire.len() <= usize::from(OVERHEAD) {
        return None;
    }
    let mut payload = wire[8..].to_vec();
    mask(password, &wire[..8], &mut payload);
    Some(payload.into())
}

#[async_trait]
impl DatagramTransport for Salamander {
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
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            let mut packet = std::task::ready!(self.inner.poll_receive(context, scratch))?;
            let maximum = self.inner.payload_budget(&packet.remote).receive();
            if packet.payload.len() > usize::from(maximum) {
                continue;
            }
            if let Some(payload) = decode(&self.password, packet.payload) {
                packet.payload = payload;
                return std::task::Poll::Ready(Ok(packet));
            }
        }
        context.waker().wake_by_ref();
        std::task::Poll::Pending
    }
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.inner.payload_budget(peer).subtract_overhead(8, 8)
    }
    fn send_owned(
        &mut self,
        packet: Datagram,
    ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
        if packet.payload.is_empty()
            || packet.payload.len() > usize::from(self.payload_budget(&packet.remote).transmit())
        {
            return Err(packet);
        }
        let mut encoded = packet;
        let plain = std::mem::take(&mut encoded.payload);
        encoded.payload = encode(&self.password, rand::random(), &plain);
        self.inner.send_owned(encoded).map_err(|mut packet| {
            packet.payload = plain;
            packet
        })
    }
    async fn send(&mut self, mut packet: Datagram) -> Result<(), DispatchError> {
        if packet.payload.is_empty()
            || packet.payload.len() > usize::from(self.payload_budget(&packet.remote).transmit())
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        packet.payload = encode(&self.password, rand::random(), &packet.payload);
        self.inner.send(packet).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                let mut packet = self.inner.receive().await?;
                let maximum = self.inner.payload_budget(&packet.remote).receive();
                if packet.payload.len() > usize::from(maximum) {
                    continue;
                }
                if let Some(payload) = decode(&self.password, packet.payload) {
                    packet.payload = payload;
                    return Ok(packet);
                }
            }
            tokio::task::yield_now().await;
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };
    use tokio::sync::mpsc;

    struct Packets {
        shared: bool,
        first: Destination,
        send: mpsc::Sender<Datagram>,
        receive: mpsc::Receiver<Datagram>,
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DatagramTransport for Packets {
        fn supports_shared_destinations(&self) -> bool {
            self.shared
        }

        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            DatagramBudget::new(2048, 2048)
        }

        fn supports_poll_receive(&self) -> bool {
            true
        }

        fn poll_receive(
            &mut self,
            cx: &mut Context<'_>,
            _: &mut Vec<u8>,
        ) -> Poll<Result<Datagram, DispatchError>> {
            if self.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(DispatchError::NotAllowed));
            }
            self.receive
                .poll_recv(cx)
                .map(|packet| packet.ok_or(DispatchError::NotAllowed))
        }

        fn send_owned(
            &mut self,
            packet: Datagram,
        ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
            if self.closed.load(Ordering::Acquire) || (!self.shared && packet.remote != self.first)
            {
                return Err(packet);
            }
            let send = self.send.clone();
            Ok(Box::pin(async move {
                send.send(packet)
                    .await
                    .map_err(|_| DispatchError::NotAllowed)
            }))
        }

        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            self.send_owned(packet)
                .map_err(|_| DispatchError::NotAllowed)?
                .await
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::poll_fn(|cx| self.poll_receive(cx, &mut Vec::new())).await
        }

        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[tokio::test]
    async fn salamander_memory_and_pacer_preserve_address_sharing_owned_send_and_close() {
        for shared in [false, true] {
            let (send, mut sent) = mpsc::channel(4);
            let (reply, receive) = mpsc::channel(4);
            let closed = Arc::new(AtomicBool::new(false));
            let first = Destination::Ip("192.0.2.1:443".parse().unwrap());
            let second = Destination::Ip("[2001:db8::2]:8443".parse().unwrap());
            let mut wrapped = Arc::new(super::super::bandwidth::Bandwidth::default()).wrap(
                wrap(
                    Box::new(Packets {
                        shared,
                        first: first.clone(),
                        send,
                        receive,
                        closed: closed.clone(),
                    }),
                    "memory-obfs",
                ),
                1400,
            );
            assert_eq!(wrapped.supports_shared_destinations(), shared);
            assert!(wrapped.supports_poll_receive());
            assert_eq!(
                wrapped.payload_budget(&first),
                DatagramBudget::new(2040, 2040)
            );
            for (index, remote) in [first.clone(), second.clone()].into_iter().enumerate() {
                let packet = Datagram {
                    remote: remote.clone(),
                    payload: Bytes::from_static(b"addressed QUIC payload"),
                    sniffed_domain: None,
                };
                if !shared && index == 1 {
                    assert!(wrapped.send(packet).await.is_err());
                    assert!(sent.try_recv().is_err());
                    continue;
                }
                if index == 0 {
                    wrapped.send(packet.clone()).await.unwrap();
                } else {
                    wrapped
                        .send_owned(packet.clone())
                        .expect("owned send supported")
                        .await
                        .unwrap();
                }
                let wire = sent.recv().await.unwrap();
                assert_eq!(wire.remote, remote);
                assert_eq!(
                    wire.payload.len(),
                    packet.payload.len() + usize::from(OVERHEAD)
                );
                assert_eq!(
                    decode(b"memory-obfs", wire.payload.clone()).unwrap(),
                    packet.payload
                );
                reply.send(wire).await.unwrap();
                let received = if index == 0 {
                    std::future::poll_fn(|cx| wrapped.poll_receive(cx, &mut Vec::new()))
                        .await
                        .unwrap()
                } else {
                    wrapped.receive().await.unwrap()
                };
                assert_eq!(received.remote, remote);
                assert_eq!(received.payload, packet.payload);
            }
            wrapped.close().await.unwrap();
            assert!(closed.load(Ordering::Acquire));
            assert!(
                wrapped
                    .send(Datagram {
                        remote: first,
                        payload: Bytes::from_static(b"closed"),
                        sniffed_domain: None
                    })
                    .await
                    .is_err()
            );
            assert!(wrapped.receive().await.is_err());
        }
    }

    #[test]
    fn salamander_matches_independent_blake2b256_vector_and_rejects_short_packets() {
        // Python hashlib.blake2b(digest_size=32), password || salt; not a
        // truncated BLAKE2b-512 and not a keyed BLAKE2 MAC.
        let literal = "0001020304050607c4df23f89a88b3e3c7615199d4aaa6d88c9d92aa39a1914b372f674df11d4745e4ff03d8baa893c3";
        let wire: Vec<u8> = (0..literal.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&literal[i..i + 2], 16).unwrap())
            .collect();
        let plain: Vec<u8> = (0..40).collect();
        assert_eq!(
            encode(b"fixture-obfs", [0, 1, 2, 3, 4, 5, 6, 7], &plain),
            wire
        );
        assert_eq!(decode(b"fixture-obfs", wire.clone().into()).unwrap(), plain);
        assert_ne!(decode(b"wrong", wire.into()).unwrap(), plain);
        for size in 0..=8 {
            assert!(decode(b"fixture-obfs", vec![0; size].into()).is_none());
        }
    }
}
