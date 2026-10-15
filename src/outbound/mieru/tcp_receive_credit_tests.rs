//! Actual outbound, encrypted carrier and packet-reader receive-credit boundary.
use super::*;
use crate::{
    config::MieruHandshake,
    outbound::{DatagramRequest, OutboundConnector},
    resources::observation::ResourceProbe,
    session::{DatagramSession, Destination},
    socks5,
};
use std::future::Future;
use tokio::io::AsyncReadExt;

use super::super::{
    MieruOutbound,
    tests::{Peer, config, session},
};

const CAPACITY: usize = 32768;
const PAYLOAD: usize = 123;
const PACKETS: usize = 300;
const ENVELOPE: usize = PAYLOAD + 10 + 4;

async fn bounded<T, E: std::fmt::Display>(
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .map_err(|_| "Mieru memory operation timed out".to_owned())?
        .map_err(|error| error.to_string())
}

fn association(node: &MieruOutbound) -> Result<(Arc<Carrier>, Arc<State>), String> {
    let registry = node.client.registry.lock().unwrap();
    for carrier in registry.carriers.values() {
        if carrier.shared.business != Some(Business::UdpAssociate) {
            continue;
        }
        for state in carrier.shared.sessions.lock().unwrap().values() {
            if !state.local_closed.load(Ordering::Acquire)
                && !state.remote_closed.load(Ordering::Acquire)
            {
                return Ok((carrier.clone(), state.clone()));
            }
        }
    }
    Err("actual UDP associate state was not published".into())
}

fn packets(remote: &Destination) -> Vec<u8> {
    let mut all = Vec::new();
    for index in 0..PACKETS {
        let mut payload = vec![index as u8; PAYLOAD];
        payload[..4].copy_from_slice(&(index as u32).to_be_bytes());
        let body = socks5::encode_udp_packet(remote, &payload, usize::from(u16::MAX)).unwrap();
        all.push(0);
        all.extend_from_slice(&(body.len() as u16).to_be_bytes());
        all.extend_from_slice(&body);
        all.push(255);
    }
    assert_eq!(all.len(), PACKETS * ENVELOPE);
    // A legal packet also straddles the 32 KiB carrier-frame boundary.
    assert_ne!(CAPACITY % ENVELOPE, 0);
    all
}

async fn inject(carrier: &Carrier, state: &Arc<State>, bytes: &[u8]) -> Result<(), String> {
    // The existing real peer echoes each DATA payload as one encrypted frame.
    // Do not bypass the production writer, AEAD decoder or State::deliver.
    for chunk in bytes.chunks(CAPACITY) {
        let permit = bounded(carrier.bytes.clone().acquire_many_owned(chunk.len() as u32)).await?;
        let (done, response) = oneshot::channel();
        bounded(carrier.writer.send(WriterCommand {
            state: state.clone(),
            data: Bytes::copy_from_slice(chunk),
            piggyback: false,
            done,
            _bytes: permit,
        }))
        .await?;
        bounded(response)
            .await?
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn blocked_input(state: &State) -> Result<usize, String> {
    bounded(async {
        loop {
            // The actual packet reader holds one response in the slot and a
            // second response in its Pending send. Observe queued bytes, not
            // permits that acquire_many may already reserve for its next chunk.
            let queued = state.unread_bytes();
            if queued == state.receive_capacity() - 2 * ENVELOPE && state.unread_segments() > 0 {
                return Ok::<_, String>(queued);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

async fn verify(
    transport: &mut dyn crate::dispatch::DatagramTransport,
    remote: &Destination,
) -> Result<(), String> {
    for index in 0..PACKETS {
        let response = bounded(transport.receive()).await?;
        let mut expected = vec![index as u8; PAYLOAD];
        expected[..4].copy_from_slice(&(index as u32).to_be_bytes());
        if response.remote != *remote || response.payload.as_ref() != expected {
            return Err("coalesced UDP response sequence, payload or address differs".into());
        }
    }
    Ok(())
}

#[tokio::test]
async fn mieru_tcp_udp_receive_credit_from_outbound_bounds_coalesced_frames_and_stop() {
    let probe = ResourceProbe::default();
    let (business, closed, stopped) = probe
        .scope(async {
            let peer = Peer::new(false);
            let mut settings = config(MieruHandshake::Standard);
            settings.multiplexing = MieruMultiplexing::Low;
            let node =
                MieruOutbound::new(&settings, UpstreamPath::proxy(peer.clone()), CAPACITY).unwrap();
            let context = EstablishContext::with_timeout(Duration::from_secs(3));
            let request = DatagramRequest::new(DatagramSession::for_tun(session().source, 1500));
            let expected_capacity = usize::from(request.budget().receive())
                + usize::from(socks5::MAX_UDP_HEADER_SIZE)
                + 4;
            let mut packet = node.open_datagram(request.clone(), &context).await.unwrap();
            let (carrier, state) = association(&node).unwrap();
            let mut stopped_packet = None;
            let mut stopped_state = None;
            let mut sibling = None;
            let business = async {
                let remote = Destination::Ip("198.51.100.1:53".parse().unwrap());
                let bytes = packets(&remote);
                let next = state.next_receive.load(Ordering::Acquire);
                inject(&carrier, &state, &bytes).await?;
                let queued = blocked_input(&state).await?;
                let decoder_blocked = tokio::time::timeout(Duration::from_millis(20), async {
                    while state.next_receive.load(Ordering::Acquire) < next + 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .is_err();
                verify(packet.as_mut(), &remote).await?;
                inject(&carrier, &state, &bytes).await?;
                blocked_input(&state).await?;

                // LOW keeps the TCP sibling on its independent carrier. This
                // is not a claim of random same-carrier UDP sibling selection.
                sibling = Some(bounded(node.connect_stream(session(), &context)).await?.io);
                let sibling_capacity = node
                    .client
                    .registry
                    .lock()
                    .unwrap()
                    .carriers
                    .values()
                    .find(|carrier| carrier.shared.business == Some(Business::TcpConnect))
                    .unwrap()
                    .shared
                    .sessions
                    .lock()
                    .unwrap()
                    .values()
                    .next()
                    .unwrap()
                    .receive_capacity();
                let io = sibling.as_mut().unwrap();
                bounded(io.write_all(b"sibling")).await?;
                let mut echoed = [0; 7];
                bounded(io.read_exact(&mut echoed)).await?;
                if echoed != *b"sibling" {
                    return Err("independent TCP sibling lost data under UDP backpressure".into());
                }
                bounded(packet.close()).await?;
                if !state.cancel.is_cancelled() {
                    return Err("closing UDP did not cancel its blocked receive state".into());
                }
                bounded(io.write_all(b"resumed")).await?;
                bounded(io.read_exact(&mut echoed)).await?;
                if echoed != *b"resumed" {
                    return Err("closing UDP interrupted its TCP sibling".into());
                }

                stopped_packet = Some(bounded(node.open_datagram(request, &context)).await?);
                let (next_carrier, next_state) = association(&node)?;
                inject(&next_carrier, &next_state, &bytes).await?;
                blocked_input(&next_state).await?;
                stopped_state = Some(next_state);
                Ok::<_, String>((
                    state.receive_capacity(),
                    queued,
                    expected_capacity,
                    decoder_blocked,
                    sibling_capacity,
                ))
            }
            .await;
            let stopped = bounded(async {
                node.shutdown().await;
                Ok::<_, String>(())
            })
            .await;
            let stopped = stopped.map(|()| {
                stopped_state
                    .as_ref()
                    .is_some_and(|state| state.cancel.is_cancelled())
            });
            let mut closed = bounded(packet.close()).await;
            if let Some(packet) = stopped_packet.as_mut() {
                closed = closed.and(bounded(packet.close()).await);
            }
            drop((
                packet,
                stopped_packet,
                sibling,
                stopped_state,
                state,
                carrier,
                node,
            ));
            peer.stop().await;
            (business, closed, stopped)
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(closed.is_ok(), "{closed:?}");
    let (capacity, queued, expected, blocked, tcp_capacity) = business.unwrap();
    assert!(matches!(stopped, Ok(true)), "{stopped:?}");
    assert!(
        queued <= expected,
        "actual queued bytes {queued} exceeds credit {expected}; actual capacity {capacity}"
    );
    assert_eq!(capacity, expected, "actual outbound UDP receive credit");
    assert!(blocked, "coalesced decoder must wait for this UDP reader");
    assert_eq!(
        tcp_capacity, CAPACITY,
        "TCP business receive budget changed"
    );
}
