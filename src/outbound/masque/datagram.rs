//! Logical UDP leases share the node's existing bounded raw-IP packet path.
use super::ip::Engine;
use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::DEFAULT_ESTABLISH_TIMEOUT,
    resources::observation::{self, ResourceKind},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};
use tokio::{sync::mpsc, time::Instant};
use vole_netstack::{Packet, UdpDatagram, encode_udp_packet_into};

const FIRST_PORT: u16 = 1024;
const RESPONSE_QUEUE: usize = 64;

struct Entry {
    id: u64,
    slot: Weak<Slot>,
}
struct State {
    next_port: u16,
    next_id: u64,
    entries: HashMap<u16, Entry>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            next_port: 49152,
            next_id: 0,
            entries: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub(super) struct Registry(Mutex<State>);

struct Slot {
    port: u16,
    id: u64,
    registry: Arc<Registry>,
    sender: mpsc::Sender<Datagram>,
    maximum: u16,
    _observation: observation::Guard,
}
impl Registry {
    fn open(
        self: &Arc<Self>,
        maximum: u16,
    ) -> Result<(Arc<Slot>, mpsc::Receiver<Datagram>), DispatchError> {
        let mut state = self.0.lock().unwrap();
        for _ in FIRST_PORT..=u16::MAX {
            let port = state.next_port;
            state.next_port = if port == u16::MAX {
                FIRST_PORT
            } else {
                port + 1
            };
            if state
                .entries
                .get(&port)
                .is_some_and(|entry| entry.slot.strong_count() > 0)
            {
                continue;
            }
            state.next_id = state.next_id.checked_add(1).ok_or_else(|| {
                DispatchError::Other("MASQUE UDP lease identifiers exhausted".into())
            })?;
            let id = state.next_id;
            let (sender, receiver) = mpsc::channel(RESPONSE_QUEUE);
            let slot = Arc::new(Slot {
                port,
                id,
                registry: self.clone(),
                sender,
                maximum,
                _observation: observation::track(ResourceKind::Association),
            });
            state.entries.insert(
                port,
                Entry {
                    id,
                    slot: Arc::downgrade(&slot),
                },
            );
            return Ok((slot, receiver));
        }
        Err(DispatchError::Other(
            "MASQUE UDP source ports exhausted".into(),
        ))
    }

    pub fn deliver(&self, source: SocketAddr, destination: SocketAddr, payload: &[u8]) {
        let slot = self
            .0
            .lock()
            .unwrap()
            .entries
            .get(&destination.port())
            .and_then(|entry| entry.slot.upgrade());
        let Some(slot) = slot.filter(|slot| payload.len() <= usize::from(slot.maximum)) else {
            return;
        };
        // Reserve before copying: a slow consumer drops this UDP reply without
        // allocating another packet or blocking TCP/control ingress.
        if let Ok(permit) = slot.sender.try_reserve() {
            permit.send(Datagram {
                remote: Destination::Ip(source),
                payload: Bytes::copy_from_slice(payload),
                sniffed_domain: None,
            });
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self.registry.0.lock().unwrap();
        if state
            .entries
            .get(&self.port)
            .is_some_and(|entry| entry.id == self.id)
        {
            state.entries.remove(&self.port);
        }
        if state.entries.capacity() > state.entries.len().saturating_mul(4).max(64) {
            state.entries.shrink_to_fit();
        }
    }
}

pub(super) struct Datagrams {
    engine: Arc<Engine>,
    slot: Option<Arc<Slot>>,
    receiver: mpsc::Receiver<Datagram>,
    resolution: ResolutionContext,
    budget: DatagramBudget,
    frame: Vec<u8>,
}
impl Datagrams {
    pub fn new(
        engine: Arc<Engine>,
        budget: DatagramBudget,
        resolution: ResolutionContext,
    ) -> Result<Self, DispatchError> {
        if engine.cancel.is_cancelled() {
            return Err(DispatchError::ConnectionRefused);
        }
        let maximum = engine
            .client
            .prefixes()
            .map(|prefix| {
                let (overhead, wire_limit) = if prefix.address.is_ipv4() {
                    (28, 65507)
                } else {
                    (48, 65527)
                };
                engine
                    .client
                    .receive_packet_limit
                    .saturating_sub(overhead)
                    .min(wire_limit)
            })
            .max()
            .unwrap_or(0)
            .min(usize::from(budget.receive()));
        let (slot, receiver) = engine
            .registry
            .open(u16::try_from(maximum).expect("UDP wire limit fits u16"))?;
        if engine.cancel.is_cancelled() {
            return Err(DispatchError::ConnectionRefused);
        }
        Ok(Self {
            engine,
            slot: Some(slot),
            receiver,
            resolution,
            budget,
            frame: Vec::new(),
        })
    }

    fn port(&self) -> Result<u16, DispatchError> {
        self.slot
            .as_ref()
            .map(|slot| slot.port)
            .ok_or(DispatchError::ConnectionRefused)
    }
}
#[async_trait]
impl DatagramTransport for Datagrams {
    fn supports_shared_destinations(&self) -> bool {
        // One inner source-port lease can address multiple IP destinations;
        // the shared IP tunnel already owns the physical transport.
        true
    }
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        let overhead = match peer {
            Destination::Ip(peer) if peer.is_ipv4() => 28,
            Destination::Ip(_) => 48,
            Destination::Domain { .. } if self.engine.client.has_ipv6() => 48,
            Destination::Domain { .. } => 28,
        };
        let wire_maximum = if overhead == 28 { 65507 } else { 65527 };
        let cap = |limit: usize| {
            u16::try_from(limit.saturating_sub(overhead).min(wire_maximum))
                .expect("UDP wire limit fits u16")
        };
        self.budget.intersect(DatagramBudget::new(
            cap(self.engine.mtu),
            cap(self.engine.client.receive_packet_limit),
        ))
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        let port = self.port()?;
        if datagram.payload.len() > usize::from(self.budget.transmit()) {
            return Err(DispatchError::Other(
                "MASQUE datagram exceeds transmit budget".into(),
            ));
        }
        let deadline = Instant::now() + DEFAULT_ESTABLISH_TIMEOUT;
        let cancellation = self.engine.cancel.clone();
        let operation = async {
            let destination = self
                .engine
                .resolve(&datagram.remote, &self.resolution, deadline)
                .await?;
            if datagram.payload.len()
                > usize::from(
                    self.payload_budget(&Destination::Ip(destination))
                        .transmit(),
                )
            {
                return Err(DispatchError::Other(
                    "MASQUE datagram exceeds transmit budget".into(),
                ));
            }
            let source = SocketAddr::new(self.engine.local(destination.ip())?, port);
            encode_udp_packet_into(
                &UdpDatagram::new(source, destination, datagram.payload),
                self.engine.mtu,
                &mut self.frame,
            )
            .map_err(|_| DispatchError::Other("invalid MASQUE datagram".into()))?;
            let packet = Packet::new(Bytes::copy_from_slice(&self.frame));
            self.engine
                .tx
                .send(packet)
                .await
                .map_err(|_| DispatchError::ConnectionRefused)
        };
        tokio::select! {biased;
            ()=cancellation.cancelled()=>Err(DispatchError::ConnectionRefused),
            result=tokio::time::timeout_at(deadline,operation)=>result.map_err(|_|DispatchError::TimedOut)?,
        }
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.port()?;
        tokio::select! {biased;
            ()=self.engine.cancel.cancelled()=>Err(DispatchError::ConnectionRefused),
            datagram=self.receiver.recv()=>datagram.ok_or(DispatchError::ConnectionRefused),
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.slot.take();
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
        self.frame = Vec::new();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masque_udp_leases_bound_replies_without_retaining_closed_ports() {
        let registry = Arc::new(Registry::default());
        let (first, mut receiver) = registry.open(4).unwrap();
        let (second, mut other) = registry.open(4).unwrap();
        assert_ne!(first.port, second.port);
        let remote = "192.0.2.1:53".parse().unwrap();
        let destination = SocketAddr::new("10.0.0.2".parse().unwrap(), first.port);
        registry.deliver(remote, destination, b"oversized");
        assert!(receiver.try_recv().is_err());
        for value in 0..=RESPONSE_QUEUE {
            registry.deliver(remote, destination, &[u8::try_from(value).unwrap()]);
        }
        for value in 0..RESPONSE_QUEUE {
            let datagram = receiver.try_recv().unwrap();
            assert_eq!(datagram.remote, Destination::Ip(remote));
            assert_eq!(&datagram.payload[..], &[u8::try_from(value).unwrap()]);
        }
        assert!(receiver.try_recv().is_err());
        assert!(other.try_recv().is_err());
        registry.deliver(remote, destination, b"back");
        assert_eq!(&receiver.try_recv().unwrap().payload[..], b"back");
        let port = first.port;
        drop(first);
        assert!(!registry.0.lock().unwrap().entries.contains_key(&port));
        registry.deliver(remote, destination, b"late");
        assert!(receiver.try_recv().is_err());
        drop(second);
        assert!(registry.0.lock().unwrap().entries.is_empty());
    }
}
