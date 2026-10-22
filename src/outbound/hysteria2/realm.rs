//! Client-only Realm setup. The owning Hysteria driver retains every UDP
//! candidate across cancellation and closes them before its Stop barrier.
mod http;
mod wire;
use crate::{
    config::Hysteria2Realm,
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{DatagramRequest, EstablishContext, UpstreamPath},
    security::StandardTlsClient,
    session::{Datagram, DatagramSession, Destination},
};
use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{io, net::SocketAddr, time::Duration};
use tokio::time::{Instant, timeout};
pub(super) fn fail() -> io::Error {
    io::Error::other("Hysteria2 Realm exchange failed")
}
struct Candidate {
    transport: Box<dyn DatagramTransport>,
    ipv6: bool,
    mapped: Vec<SocketAddr>,
}
#[derive(Default)]
pub(super) struct Pending {
    candidates: Vec<Option<Candidate>>,
}
impl Pending {
    pub async fn stop(&mut self) {
        for entry in &mut self.candidates {
            if let Some(candidate) = entry.as_mut() {
                let _ = timeout(Duration::from_secs(1), candidate.transport.close()).await;
            }
            entry.take();
        }
        self.candidates.clear();
    }
    pub async fn open(
        &mut self,
        options: &Hysteria2Realm,
        tls: Option<&StandardTlsClient>,
        upstream: &UpstreamPath,
        datagram: &DatagramSession,
        context: &EstablishContext,
        budget: DatagramBudget,
    ) -> Result<(Box<dyn DatagramTransport>, SocketAddr), DispatchError> {
        let mut servers = Vec::new();
        for server in &options.stun_servers {
            let resolved = upstream
                .for_server(server, false)
                .datagram_server(server, context)
                .await?;
            let address = context.resolve_ip(&resolved).await?;
            if !servers.contains(&address) {
                servers.push(address);
            }
        }
        for ipv6 in [false, true] {
            if !servers.iter().any(|server| server.is_ipv6() == ipv6) {
                continue;
            }
            let raw = upstream
                .open_datagram(
                    DatagramRequest::new(datagram.clone())
                        .with_budget(budget)
                        .with_udp_receive_buffer_size(2 * 1024 * 1024),
                    context,
                )
                .await?;
            self.candidates.push(Some(Candidate {
                transport: raw,
                ipv6,
                mapped: Vec::new(),
            }));
        }
        // At most two borrowed futures; no detached DNS/STUN or punch workers.
        let discovery = self.candidates.iter_mut().map(|entry| {
            let servers = &servers;
            async move {
                let entry = entry.as_mut().unwrap();
                let family: Vec<_> = servers
                    .iter()
                    .copied()
                    .filter(|server| server.is_ipv6() == entry.ipv6)
                    .collect();
                if let Ok(mapped) = discover(&mut *entry.transport, &family).await {
                    entry.mapped = mapped;
                }
            }
        });
        futures_util::future::join_all(discovery).await;
        let addresses: Vec<_> = self
            .candidates
            .iter()
            .flatten()
            .flat_map(|entry| entry.mapped.iter().copied())
            .collect();
        if addresses.is_empty() {
            return Err(fail().into());
        }
        let metadata = wire::Metadata {
            nonce: rand::random(),
            key: rand::random(),
        };
        let (peers, metadata) = http::connect(
            options, tls, upstream, datagram, context, &addresses, &metadata,
        )
        .await?;
        let mut futures = FuturesUnordered::new();
        for (index, entry) in self.candidates.iter_mut().enumerate() {
            let entry = entry.as_mut().unwrap();
            if entry.mapped.is_empty() {
                continue;
            }
            let candidates = candidates(&peers, entry.ipv6)?;
            let meta = metadata.clone();
            futures.push(async move {
                (
                    index,
                    punch(&mut *entry.transport, &candidates, &meta).await,
                )
            });
        }
        let mut winner = None;
        while let Some((index, result)) = futures.next().await {
            if let Ok(peer) = result {
                winner = Some((index, peer));
                break;
            }
        }
        drop(futures);
        let (index, peer) = winner.ok_or_else(fail)?;
        // Leave the winner in Pending until every await is complete. Even a
        // cancellation during loser cleanup retains all resources for Stop.
        for (other, entry) in self.candidates.iter_mut().enumerate() {
            if other == index {
                continue;
            }
            if let Some(candidate) = entry.as_mut() {
                let _ = timeout(Duration::from_secs(1), candidate.transport.close()).await;
            }
            entry.take();
        }
        let candidate = self.candidates[index].take().unwrap();
        self.candidates.clear();
        Ok((candidate.transport, peer))
    }
}
struct Request {
    server: SocketAddr,
    id: [u8; 12],
    done: bool,
}
async fn discover(
    transport: &mut dyn DatagramTransport,
    servers: &[SocketAddr],
) -> Result<Vec<SocketAddr>, DispatchError> {
    let mut requests: Vec<_> = servers
        .iter()
        .map(|server| Request {
            server: *server,
            id: rand::random(),
            done: false,
        })
        .collect();
    let mut addresses = Vec::new();
    for duration in [
        Duration::from_millis(500),
        Duration::from_secs(2),
        Duration::from_secs(4),
    ] {
        if requests.iter().all(|request| request.done) {
            break;
        }
        let mut sent = false;
        for request in &requests {
            if !request.done {
                sent |= transport
                    .send(Datagram {
                        remote: Destination::Ip(request.server),
                        payload: wire::stun_request(request.id).into(),
                        sniffed_domain: None,
                    })
                    .await
                    .is_ok();
            }
        }
        if !sent {
            continue;
        }
        let deadline = Instant::now() + duration;
        loop {
            let packet = tokio::select! {()=tokio::time::sleep_until(deadline)=>break,packet=transport.receive()=>packet?};
            tokio::task::yield_now().await;
            if packet.payload.len() > 1500 {
                continue;
            }
            let Destination::Ip(source) = packet.remote else {
                continue;
            };
            for request in &mut requests {
                if request.done || request.server != source {
                    continue;
                }
                if let Some(address) = wire::stun_response(&packet.payload, &request.id)
                    && address.is_ipv6() == source.is_ipv6()
                {
                    request.done = true;
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                    break;
                }
            }
            if requests.iter().all(|request| request.done) {
                break;
            }
            tokio::task::yield_now().await;
        }
    }
    if addresses.is_empty() {
        Err(fail().into())
    } else {
        Ok(addresses)
    }
}
fn candidates(peers: &[SocketAddr], ipv6: bool) -> Result<Vec<SocketAddr>, DispatchError> {
    let mut out = Vec::new();
    for peer in peers.iter().filter(|peer| peer.is_ipv6() == ipv6) {
        if !out.contains(peer) {
            out.push(*peer);
        }
    }
    let originals = out.clone();
    // Match the reference's small, predictable symmetric-NAT port expansion;
    // cap the entire attempt before sending, never an unbounded subnet scan.
    let mut hosts = Vec::new();
    if !ipv6 {
        for peer in &originals {
            if hosts.contains(&peer.ip()) {
                continue;
            }
            hosts.push(peer.ip());
            let mut ports: Vec<_> = originals
                .iter()
                .filter(|other| other.ip() == peer.ip())
                .map(SocketAddr::port)
                .collect();
            ports.sort_unstable();
            ports.dedup();
            if ports.len() < 2 || ports.windows(2).any(|pair| pair[1] - pair[0] > 4) {
                continue;
            }
            let end = ports[ports.len() - 1].saturating_add(4);
            let mut added = 0;
            for port in ports[0]..=end {
                let candidate = SocketAddr::new(peer.ip(), port);
                if !out.contains(&candidate) {
                    out.push(candidate);
                    added += 1;
                    if added == 32 {
                        break;
                    }
                }
                if out.len() > 128 {
                    return Err(fail().into());
                }
            }
        }
    }
    Ok(out)
}
async fn punch(
    transport: &mut dyn DatagramTransport,
    peers: &[SocketAddr],
    metadata: &wire::Metadata,
) -> Result<SocketAddr, DispatchError> {
    if peers.is_empty() {
        return Err(fail().into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut next = Instant::now();
    loop {
        if Instant::now() >= deadline {
            return Err(DispatchError::TimedOut);
        }
        if Instant::now() >= next {
            for peer in peers {
                let packet = Datagram {
                    remote: Destination::Ip(*peer),
                    payload: Bytes::from(wire::encode(1, metadata)),
                    sniffed_domain: None,
                };
                let _ = transport.send(packet).await;
            }
            next = Instant::now() + Duration::from_millis(100);
        }
        let packet = tokio::select! {()=tokio::time::sleep_until(next.min(deadline))=>continue,packet=transport.receive()=>packet?};
        tokio::task::yield_now().await;
        let Destination::Ip(peer) = packet.remote else {
            continue;
        };
        if peer.is_ipv6() != peers[0].is_ipv6()
            || peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
        {
            continue;
        }
        if let Some(kind) = wire::decode(&packet.payload, metadata) {
            if kind == 1 {
                transport
                    .send(Datagram {
                        remote: Destination::Ip(peer),
                        payload: Bytes::from(wire::encode(2, metadata)),
                        sniffed_domain: None,
                    })
                    .await?;
            }
            return Ok(peer);
        }
        tokio::task::yield_now().await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn realm_candidates_keep_family_and_bound_predictable_port_probes() {
        let peers = [
            "192.0.2.1:40000".parse().unwrap(),
            "192.0.2.1:40002".parse().unwrap(),
            "[2001:db8::1]:40003".parse().unwrap(),
        ];
        let v4 = candidates(&peers, false).unwrap();
        assert!(v4.contains(&"192.0.2.1:40006".parse().unwrap()));
        assert!(v4.iter().all(SocketAddr::is_ipv4));
        assert!(v4.len() <= 128);
        assert_eq!(candidates(&peers, true).unwrap(), vec![peers[2]]);
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Waiting(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl DatagramTransport for Waiting {
        fn supports_shared_destinations(&self) -> bool {
            false
        }

        async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }
    #[tokio::test]
    async fn realm_cancelled_discovery_keeps_candidates_for_synchronous_cleanup() {
        let closed = Arc::new(AtomicUsize::new(0));
        let mut pending = Pending::default();
        for ipv6 in [false, true] {
            pending.candidates.push(Some(Candidate {
                transport: Box::new(Waiting(closed.clone())),
                ipv6,
                mapped: Vec::new(),
            }));
        }
        let servers = ["192.0.2.1:3478".parse().unwrap()];
        {
            let candidate = pending.candidates[0].as_mut().unwrap();
            assert!(
                timeout(
                    Duration::from_millis(1),
                    discover(&mut *candidate.transport, &servers)
                )
                .await
                .is_err()
            );
        }
        assert_eq!(pending.candidates.iter().flatten().count(), 2);
        pending.stop().await;
        assert_eq!(closed.load(Ordering::Acquire), 2);
        assert!(pending.candidates.is_empty());
        pending.stop().await;
        assert_eq!(closed.load(Ordering::Acquire), 2);
    }
}
