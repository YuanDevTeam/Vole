use super::*;
use crate::{
    config::MkcpHeader,
    dispatch::{DatagramBudget, DispatchError},
};
use std::{collections::BTreeSet, sync::atomic::AtomicUsize};
use tokio::sync::mpsc;

struct Packets {
    to_peer: mpsc::Sender<Datagram>,
    to_client: mpsc::Receiver<Datagram>,
    closed: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl DatagramTransport for Packets {
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1350, 1362)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        self.to_peer
            .send(packet)
            .await
            .map_err(|_| DispatchError::HostUnreachable)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.to_client
            .recv()
            .await
            .ok_or(DispatchError::HostUnreachable)
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}
fn packets() -> (
    Packets,
    mpsc::Receiver<Datagram>,
    mpsc::Sender<Datagram>,
    Arc<AtomicBool>,
) {
    // A bounded in-memory wire: no socket, resolver, TUN or host process.
    let (to_peer, peer) = mpsc::channel(8);
    let (client, to_client) = mpsc::channel(8);
    let closed = Arc::new(AtomicBool::new(false));
    (
        Packets {
            to_peer,
            to_client,
            closed: closed.clone(),
        },
        peer,
        client,
        closed,
    )
}
async fn reply(
    output: &mpsc::Sender<Datagram>,
    codec: &mut wire::Codec,
    peer: &Destination,
    segment: Vec<u8>,
) {
    output
        .send(Datagram {
            remote: peer.clone(),
            payload: Bytes::from(codec.seal(&segment).unwrap()),
            sniffed_domain: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn mkcp_memory_driver_retransmits_reorders_flushes_and_joins() {
    for (seed, header) in [("", MkcpHeader::None), ("memory seed", MkcpHeader::Dtls)] {
        let options = MkcpOptions {
            seed: Arc::from(seed),
            header,
            ..MkcpOptions::default()
        };
        let (transport, mut incoming, output, closed) = packets();
        let address = "192.0.2.1:443".parse().unwrap();
        let peer = Destination::Ip(address);
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let mut codec = wire::Codec::new(&options).unwrap();
        let worker = tokio::spawn(async move {
            let mut dropped = false;
            let mut next = 0u32;
            let mut seen = BTreeSet::new();
            while let Some(packet) = incoming.recv().await {
                let plain = codec.open(&packet.payload, 1362).unwrap();
                let conv = u16::from_be_bytes(plain[..2].try_into().unwrap());
                let (segment, size) = wire::parse(&plain, conv).unwrap();
                assert_eq!(size, plain.len());
                match segment {
                    wire::Segment::Data {
                        number,
                        time,
                        payload,
                        ..
                    } => {
                        // Independently model only a peer's ordered ACK cursor;
                        // deliberately lose its first packet and echo later
                        // packets out of order. No State instance is reused.
                        if !dropped {
                            dropped = true;
                            continue;
                        }
                        let first = !state::before(number, next) && seen.insert(number);
                        if first {
                            count.fetch_add(payload.len(), Ordering::AcqRel);
                        }
                        while seen.remove(&next) {
                            next = next.wrapping_add(1);
                        }
                        reply(
                            &output,
                            &mut codec,
                            &peer,
                            wire::ack(conv, 0, next.wrapping_add(32), next, time, &[number]),
                        )
                        .await;
                        if first {
                            reply(
                                &output,
                                &mut codec,
                                &peer,
                                wire::data(conv, 0, time, number, 0, payload),
                            )
                            .await;
                        }
                    }
                    wire::Segment::Control { command: 2, .. } => break,
                    _ => {}
                }
            }
        });
        let tasks = TaskTracker::new();
        let cancel = CancellationToken::new();
        let mut stream = connect(
            Box::new(transport),
            address,
            options,
            cancel.clone(),
            &tasks,
        )
        .unwrap();
        let payload: Vec<u8> = (0..20_000).map(|n| (n % 251) as u8).collect();
        timeout(Duration::from_secs(3), async {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(received.load(Ordering::Acquire), payload.len());
            let mut echoed = vec![0; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        })
        .await
        .unwrap();
        drop(stream);
        tasks.close();
        timeout(Duration::from_secs(1), tasks.wait()).await.unwrap();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(cancel.is_cancelled());
        assert!(closed.load(Ordering::Acquire));
    }
}

#[tokio::test]
async fn mkcp_memory_flush_waits_for_peer_ack_and_stop_cancels_io() {
    let options = MkcpOptions::default();
    let (transport, mut incoming, output, closed) = packets();
    let address = "192.0.2.1:443".parse().unwrap();
    let cancel = CancellationToken::new();
    let tasks = TaskTracker::new();
    let mut stream = connect(
        Box::new(transport),
        address,
        options.clone(),
        cancel.clone(),
        &tasks,
    )
    .unwrap();
    stream.write_all(b"accepted only after ACK").await.unwrap();
    let first = timeout(Duration::from_secs(1), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    let mut codec = wire::Codec::new(&options).unwrap();
    let plain = codec.open(&first.payload, 1350).unwrap();
    let conv = u16::from_be_bytes(plain[..2].try_into().unwrap());
    let (wire::Segment::Data { time, number, .. }, _) = wire::parse(&plain, conv).unwrap() else {
        panic!("expected data")
    };
    assert!(
        timeout(Duration::from_millis(20), stream.flush())
            .await
            .is_err()
    );
    let ack = wire::ack(conv, 0, 32, number + 1, time, &[number]);
    // Valid authentication from another source must not acknowledge this
    // immutable peer, and a corrupted packet must not acknowledge either.
    reply(
        &output,
        &mut codec,
        &Destination::Ip("192.0.2.2:443".parse().unwrap()),
        ack.clone(),
    )
    .await;
    assert!(
        timeout(Duration::from_millis(20), stream.flush())
            .await
            .is_err()
    );
    let mut damaged = codec.seal(&ack).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    output
        .send(Datagram {
            remote: Destination::Ip(address),
            payload: Bytes::from(damaged),
            sniffed_domain: None,
        })
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(20), stream.flush())
            .await
            .is_err()
    );
    reply(&output, &mut codec, &Destination::Ip(address), ack).await;
    timeout(Duration::from_secs(1), stream.flush())
        .await
        .unwrap()
        .unwrap();
    // A pending receive/write owns no detached worker after the node token.
    cancel.cancel();
    tasks.close();
    timeout(Duration::from_secs(1), tasks.wait()).await.unwrap();
    assert!(closed.load(Ordering::Acquire));
    assert!(stream.write_all(b"late").await.is_err());
}
