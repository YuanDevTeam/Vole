use super::engine::Engine;
use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::DEFAULT_ESTABLISH_TIMEOUT,
    resources::observation::{self, ResourceKind},
    session::{Datagram, DatagramSession, Destination},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::mpsc;
use tokio::time::Instant;
use vole_netstack::{Packet, UdpDatagram, encode_udp_packet_into};

const FIRST_PORT: u16 = 1024;
const RESPONSE_QUEUE: usize = 64;
struct Entry {
    id: u64,
    slot: Weak<Slot>,
}
struct State {
    next: u16,
    id: u64,
    entries: HashMap<u16, Entry>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            next: 49152,
            id: 0,
            entries: HashMap::new(),
        }
    }
}
#[derive(Default)]
pub(super) struct Registry(Mutex<State>);
pub(super) struct Slot {
    pub port: u16,
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
            let port = state.next;
            state.next = if port == u16::MAX {
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
            state.id = state.id.checked_add(1).ok_or_else(|| {
                DispatchError::Other("WireGuard UDP lease identifiers exhausted".into())
            })?;
            let id = state.id;
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
            "WireGuard UDP source ports exhausted".into(),
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
        if let Some(slot) = slot.filter(|slot| payload.len() <= usize::from(slot.maximum)) {
            let _ = slot.sender.try_send(Datagram {
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
    session: DatagramSession,
    budget: DatagramBudget,
    frame: Vec<u8>,
}
impl Datagrams {
    pub fn new(
        engine: Arc<Engine>,
        request: DatagramBudget,
        resolution: ResolutionContext,
        session: DatagramSession,
    ) -> Result<Self, DispatchError> {
        let overhead = if engine.ipv6.is_some() { 48 } else { 28 };
        let maximum = (engine.mtu - overhead) as u16;
        let budget = DatagramBudget::new(
            maximum.min(request.transmit()),
            maximum.min(request.receive()),
        );
        let (slot, receiver) = engine.registry.open(budget.receive())?;
        let mtu = engine.mtu;
        Ok(Self {
            engine,
            slot: Some(slot),
            receiver,
            resolution,
            session,
            budget,
            frame: Vec::with_capacity(mtu),
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
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        let port = self.port()?;
        if datagram.payload.len() > usize::from(self.budget.transmit()) {
            return Err(DispatchError::Other(
                "WireGuard datagram exceeds transmit budget".into(),
            ));
        }
        let deadline = Instant::now() + DEFAULT_ESTABLISH_TIMEOUT;
        let destination =
            super::resolver::resolve(&self.engine, &datagram.remote, &self.resolution, deadline)
                .await?;
        let context = crate::outbound::EstablishContext::with_resolution(
            DEFAULT_ESTABLISH_TIMEOUT,
            self.resolution.clone(),
        )
        .with_metadata(&self.session.metadata)
        .capped_by(deadline);
        let channel = self
            .engine
            .peer(destination.ip(), self.session.clone(), &context)
            .await?;
        let source = SocketAddr::new(self.engine.local(destination.ip())?, port);
        encode_udp_packet_into(
            &UdpDatagram::new(source, destination, datagram.payload),
            self.engine.mtu,
            &mut self.frame,
        )
        .map_err(|_| DispatchError::Other("invalid WireGuard datagram".into()))?;
        let packet = Packet::new(Bytes::copy_from_slice(&self.frame));
        tokio::select! {biased;
            ()=self.engine.cancel.cancelled()=>Err(DispatchError::ConnectionRefused),
            result=tokio::time::timeout_at(deadline,channel.tx.send(packet))=>result.map_err(|_|DispatchError::TimedOut)?.map_err(|_|DispatchError::ConnectionRefused),
        }
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.port()?;
        tokio::select! {biased;()=self.engine.cancel.cancelled()=>Err(DispatchError::ConnectionRefused),datagram=self.receiver.recv()=>datagram.ok_or(DispatchError::ConnectionRefused)}
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.slot.take();
        self.receiver.close();
        Ok(())
    }
}

pub(super) fn local_destination(
    config: &crate::config::WireGuardOutboundConfig,
    destination: IpAddr,
) -> bool {
    match destination {
        IpAddr::V4(ip) => config.ipv4 == Some(ip),
        IpAddr::V6(ip) => config.ipv6 == Some(ip),
    }
}
