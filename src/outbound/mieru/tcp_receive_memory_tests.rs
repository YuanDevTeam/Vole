//! Coalesced encrypted UDP responses through the production outbound and reader.
use super::super::{
    MieruOutbound,
    tests::{Peer, config, session},
};
use super::*;
use crate::{
    config::MieruHandshake,
    outbound::{DatagramRequest, OutboundConnector},
    resources::observation::ResourceProbe,
    session::{DatagramSession, Destination},
    socks5,
};

const CAPACITY: usize = 32768;
const PACKETS: usize = 64;
const PAYLOAD: usize = 123;
const ENVELOPE: usize = 4 + 10 + PAYLOAD;

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("Mieru memory operation timed out")
}

async fn inject(carrier: &Carrier, state: &Arc<State>, bytes: &[u8]) {
    let permit = bounded(carrier.bytes.clone().acquire_many_owned(bytes.len() as u32))
        .await
        .unwrap();
    let (done, response) = oneshot::channel();
    bounded(carrier.writer.send(WriterCommand {
        state: state.clone(),
        data: Bytes::copy_from_slice(bytes),
        piggyback: false,
        done,
        _bytes: permit,
    }))
    .await
    .unwrap();
    bounded(response).await.unwrap().unwrap();
}

async fn blocked_input(state: &State) -> usize {
    let expected = state.receive_capacity().min(PACKETS * ENVELOPE) - 2 * ENVELOPE;
    bounded(async {
        loop {
            // One response is queued and one is pending in the sole sender.
            // Semaphore waiters may reserve permits; inspect actual queued data.
            if state.unread_bytes() == expected {
                return expected;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

#[tokio::test]
async fn mieru_tcp_udp_receive_memory_tracks_the_datagram_budget() {
    let probe = ResourceProbe::default();
    let (capacity, queued, expected) = probe
        .scope(async {
            let peer = Peer::new(false);
            let mut settings = config(MieruHandshake::Standard);
            settings.multiplexing = MieruMultiplexing::Low;
            let node =
                MieruOutbound::new(&settings, UpstreamPath::proxy(peer.clone()), CAPACITY).unwrap();
            let context = EstablishContext::with_timeout(Duration::from_secs(3));
            let request = DatagramRequest::new(DatagramSession::for_tun(session().source, 1500));
            let expected = usize::from(request.budget().receive())
                + usize::from(socks5::MAX_UDP_HEADER_SIZE)
                + 4;
            let mut packet = bounded(node.open_datagram(request, &context))
                .await
                .unwrap();
            let carrier = node
                .client
                .registry
                .lock()
                .unwrap()
                .carriers
                .values()
                .next()
                .unwrap()
                .clone();
            let state = carrier
                .shared
                .sessions
                .lock()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .clone();
            let remote = Destination::Ip("198.51.100.1:53".parse().unwrap());
            let mut bytes = Vec::new();
            for index in 0..PACKETS {
                let body = socks5::encode_udp_packet(
                    &remote,
                    &[index as u8; PAYLOAD],
                    usize::from(u16::MAX),
                )
                .unwrap();
                bytes.push(0);
                bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&body);
                bytes.push(255);
            }
            assert_eq!(bytes.len(), PACKETS * ENVELOPE);
            inject(&carrier, &state, &bytes).await;
            let queued = blocked_input(&state).await;
            for index in 0..PACKETS {
                let response = bounded(packet.receive()).await.unwrap();
                assert_eq!(response.remote, remote);
                assert_eq!(response.payload.as_ref(), [index as u8; PAYLOAD]);
            }
            inject(&carrier, &state, &bytes).await;
            blocked_input(&state).await;
            bounded(node.shutdown()).await; // Stop must not await the application reader.
            bounded(packet.close()).await.unwrap();
            let capacity = state.receive_capacity();
            drop((packet, state, carrier, node));
            peer.stop().await;
            (capacity, queued, expected)
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(
        queued <= expected,
        "queued {queued} exceeds datagram credit {expected}"
    );
    assert_eq!(capacity, expected);
}
