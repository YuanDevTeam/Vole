use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use tokio::{net::UdpSocket, sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{
    session::{Datagram, DatagramSession, InboundKind, InboundMetadata, SOCKS5_UDP_PACKET_LIMIT},
    socks5::decode_udp_packet,
};

pub(super) const QUEUE_CAPACITY: usize = 16;
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

struct Entry {
    sender: mpsc::Sender<Datagram>,
    cancellation: CancellationToken,
    last_activity: Instant,
    source: Arc<Mutex<SocketAddr>>,
}

impl Entry {
    fn expired(&self, now: Instant) -> bool {
        self.cancellation.is_cancelled()
            || self.sender.is_closed()
            || now.duration_since(self.last_activity) >= IDLE_TIMEOUT
    }
}

/// Port zero is the single unbound slot for an IP and its IPv6 scope. Entries
/// are never recreated by UDP traffic; only a negotiated TCP control connection
/// can insert one.
#[derive(Default)]
pub(super) struct Associations(Mutex<HashMap<SocketAddr, Entry>>);

pub(super) struct Lease {
    pub(super) metadata: InboundMetadata,
    registry: Arc<Associations>,
    pub(super) cancellation: CancellationToken,
    pub(super) source: Arc<Mutex<SocketAddr>>,
}

impl Lease {
    pub(super) fn session(&self) -> DatagramSession {
        DatagramSession::new(InboundKind::Socks5, *self.source.lock().unwrap())
            .with_metadata(self.metadata.clone())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Serialize removal with UDP learning/replies. A stale generation must
        // never remove a newly authorized association at the same address.
        let mut entries = self.registry.0.lock().unwrap();
        let source = *self.source.lock().unwrap();
        if entries
            .get(&source)
            .is_some_and(|entry| Arc::ptr_eq(&entry.source, &self.source))
        {
            entries.remove(&source);
        }
        self.cancellation.cancel();
    }
}

impl Associations {
    pub(super) fn register(
        self: &Arc<Self>,
        mut peer: SocketAddr,
        port: u16,
        parent: &CancellationToken,
    ) -> io::Result<(Lease, mpsc::Receiver<Datagram>)> {
        // The request carries no IPv6 zone: retain it from the authorized TCP
        // peer so the association matches recv_from's scoped UDP source.
        peer.set_port(port);
        let source = peer;
        let mut entries = self.0.lock().unwrap();
        let now = Instant::now();
        if let Some(entry) = entries.get(&source) {
            if !entry.expired(now) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ambiguous SOCKS5 UDP association",
                ));
            }
            entry.cancellation.cancel();
            entries.remove(&source);
        }
        let cancellation = parent.child_token();
        let learned_source = Arc::new(Mutex::new(source));
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        entries.insert(
            source,
            Entry {
                sender,
                cancellation: cancellation.clone(),
                last_activity: now,
                source: learned_source.clone(),
            },
        );
        Ok((
            Lease {
                metadata: InboundMetadata::new(0),
                registry: self.clone(),
                cancellation,
                source: learned_source,
            },
            receiver,
        ))
    }

    pub(super) fn enqueue(&self, source: SocketAddr, packet: &[u8], now: Instant) {
        let Ok((remote, payload)) = decode_udp_packet(packet, SOCKS5_UDP_PACKET_LIMIT) else {
            return;
        };
        let mut entries = self.0.lock().unwrap();
        let mut unbound = source;
        unbound.set_port(0);
        let key = if entries.contains_key(&source) {
            source
        } else {
            unbound
        };
        let Some(entry) = entries.get_mut(&key) else {
            return;
        };
        if entry.expired(now) {
            entry.cancellation.cancel();
            entries.remove(&key);
            return;
        }
        // Do not learn the source or refresh idle time for rejected packets.
        let Ok(permit) = entry.sender.try_reserve() else {
            return;
        };
        crate::resources::observation::observe_queue(
            crate::resources::observation::QueueKind::SocksUdp,
            QUEUE_CAPACITY - entry.sender.capacity(),
            QUEUE_CAPACITY,
        );
        *entry.source.lock().unwrap() = source;
        permit.send(Datagram {
            remote,
            payload: Bytes::copy_from_slice(payload),
            sniffed_domain: None,
        });
        entry.last_activity = now;
        if key != source {
            let entry = entries.remove(&key).unwrap();
            entries.insert(source, entry);
        }
    }

    pub(super) fn cleanup(&self, now: Instant) {
        self.0.lock().unwrap().retain(|_, entry| {
            if entry.expired(now) {
                entry.cancellation.cancel();
                false
            } else {
                true
            }
        });
    }

    /// A nonblocking send under the authorization lock makes revocation a
    /// barrier: after lease removal there can be no late reply from its worker.
    pub(super) fn try_reply(
        &self,
        lease: &Lease,
        socket: &UdpSocket,
        packet: &[u8],
    ) -> io::Result<()> {
        let mut entries = self.0.lock().unwrap();
        let source = *lease.source.lock().unwrap();
        let now = Instant::now();
        let entry = entries
            .get_mut(&source)
            .filter(|entry| Arc::ptr_eq(&entry.source, &lease.source) && !entry.expired(now))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "SOCKS5 association ended")
            })?;
        if source.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SOCKS5 source is not learned",
            ));
        }
        let written = socket.try_send_to(packet, source)?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial SOCKS5 datagram",
            ));
        }
        entry.last_activity = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{session::Destination, socks5::encode_udp_packet};

    #[tokio::test]
    async fn ingress_udp_lease_retains_verified_user_and_learned_source() {
        let registry = Arc::new(Associations::default());
        let credentials = crate::config::ProxyCredentials::new("Alice", "pass").unwrap();
        let user = credentials.authenticate(b"Alice", b"pass").unwrap();
        let weak = Arc::downgrade(&user);
        let (mut lease, mut receiver) = registry
            .register(
                "192.0.2.1:1234".parse().unwrap(),
                0,
                &CancellationToken::new(),
            )
            .unwrap();
        lease.metadata = InboundMetadata {
            local_port: 1080,
            user: Some(user),
        };
        drop(credentials);
        let source = "192.0.2.1:4321".parse().unwrap();
        let packet = encode_udp_packet(
            &Destination::Ip("203.0.113.1:53".parse().unwrap()),
            b"data",
            65507,
        )
        .unwrap();
        registry.enqueue(source, &packet, Instant::now());
        assert_eq!(receiver.recv().await.unwrap().payload.as_ref(), b"data");
        let session = lease.session();
        assert_eq!(session.source, source);
        assert_eq!(session.metadata.local_port, 1080);
        assert_eq!(session.metadata.user.as_deref(), Some("Alice"));
        assert!(!format!("{:?}", session.metadata).contains("Alice"));
        drop(lease);
        assert!(registry.0.lock().unwrap().is_empty());
        assert!(weak.upgrade().is_some());
        drop(session);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn bounded_queue_idle_expiry_and_old_generation_cannot_remove_replacement() {
        let registry = Arc::new(Associations::default());
        let parent = CancellationToken::new();
        let source: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (lease, mut receiver) = registry.register(source, source.port(), &parent).unwrap();
        let now = Instant::now();
        let packet = encode_udp_packet(
            &Destination::Ip("127.0.0.1:53".parse().unwrap()),
            b"data",
            65507,
        )
        .unwrap();
        for _ in 0..QUEUE_CAPACITY {
            registry.enqueue(source, &packet, now);
        }
        registry.enqueue(source, &packet, now + Duration::from_secs(20));
        assert_eq!(receiver.len(), QUEUE_CAPACITY);
        assert_eq!(registry.0.lock().unwrap()[&source].last_activity, now);
        registry.cleanup(now + IDLE_TIMEOUT);
        assert!(lease.cancellation.is_cancelled());
        assert!(registry.0.lock().unwrap().is_empty());
        receiver.close();
        let (replacement, _receiver) = registry.register(source, source.port(), &parent).unwrap();
        drop(lease);
        assert!(!replacement.cancellation.is_cancelled());
        assert_eq!(registry.0.lock().unwrap().len(), 1);
        drop(replacement);
        assert!(registry.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_wire_limit_passes_and_oversize_or_malformed_cannot_learn_or_refresh() {
        let registry = Arc::new(Associations::default());
        let parent = CancellationToken::new();
        let source: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (lease, mut receiver) = registry.register(source, 0, &parent).unwrap();
        let now = Instant::now();
        registry.enqueue(source, &[0, 0, 1, 1], now);
        let target = Destination::domain("d".repeat(255), 53).unwrap();
        let payload =
            vec![7; SOCKS5_UDP_PACKET_LIMIT - usize::from(crate::socks5::MAX_UDP_HEADER_SIZE)];
        let mut packet = encode_udp_packet(&target, &payload, SOCKS5_UDP_PACKET_LIMIT).unwrap();
        packet.push(7);
        registry.enqueue(source, &packet, now);
        assert_eq!(lease.source.lock().unwrap().port(), 0);
        assert!(receiver.try_recv().is_err());
        packet.pop();
        registry.enqueue(source, &packet, now);
        assert_eq!(*lease.source.lock().unwrap(), source);
        assert_eq!(receiver.try_recv().unwrap().payload.as_ref(), payload);
        registry.cleanup(now + IDLE_TIMEOUT);
        // Expired unbound/bound slots cannot be revived by a late packet.
        registry.enqueue(source, &packet, now + IDLE_TIMEOUT);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn ipv6_udp_associations_preserve_scope_for_explicit_and_learned_ports() {
        let target = Destination::domain("fixture.invalid", 53).unwrap();
        let packet = encode_udp_packet(&target, b"data", SOCKS5_UDP_PACKET_LIMIT).unwrap();
        // Synthetic interface indices exercise source matching without relying
        // on a physical link-local interface or claiming LAN interoperability.
        let peer: SocketAddr = "[fe80::1%3]:42000".parse().unwrap();
        let other_peer: SocketAddr = "[fe80::1%4]:42000".parse().unwrap();
        let source: SocketAddr = "[fe80::1%3]:10000".parse().unwrap();
        let other_source: SocketAddr = "[fe80::1%4]:10000".parse().unwrap();
        let unauthorized: SocketAddr = "[fe80::1%5]:10000".parse().unwrap();
        let wrong_port: SocketAddr = "[fe80::1%3]:10001".parse().unwrap();

        for requested_port in [10000, 0] {
            let registry = Arc::new(Associations::default());
            let parent = CancellationToken::new();
            let (lease, mut receiver) = registry.register(peer, requested_port, &parent).unwrap();
            let (other_lease, mut other_receiver) = registry
                .register(other_peer, requested_port, &parent)
                .unwrap();
            assert!(registry.register(peer, requested_port, &parent).is_err());
            let now = Instant::now();

            registry.enqueue(unauthorized, &packet, now);
            assert!(receiver.try_recv().is_err());
            assert!(other_receiver.try_recv().is_err());

            registry.enqueue(source, &packet, now);
            let datagram = receiver.try_recv().unwrap();
            assert_eq!(datagram.remote, target);
            assert_eq!(datagram.payload.as_ref(), b"data");
            assert_eq!(*lease.source.lock().unwrap(), source);
            assert!(other_receiver.try_recv().is_err());

            registry.enqueue(other_source, &packet, now);
            assert_eq!(other_receiver.try_recv().unwrap().payload.as_ref(), b"data");
            assert_eq!(*other_lease.source.lock().unwrap(), other_source);
            assert!(receiver.try_recv().is_err());

            registry.enqueue(wrong_port, &packet, now);
            assert!(receiver.try_recv().is_err());
            assert!(other_receiver.try_recv().is_err());

            drop(lease);
            registry.enqueue(source, &packet, now);
            assert!(receiver.try_recv().is_err());
            registry.enqueue(other_source, &packet, now);
            assert_eq!(other_receiver.try_recv().unwrap().payload.as_ref(), b"data");
        }
    }
}
