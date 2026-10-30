//! Real pump/codec bytes over memory IO; existing Grpc/Writes fixtures guard
//! the supplied-IO receipt implementation, which this candidate does not change.
use super::*;
use std::{
    pin::Pin,
    sync::Mutex as SyncMutex,
    task::{Context, Poll, Waker},
};
use vole_netstack::{UdpDatagram, encode_udp_packet_into, parse_udp_packet_view};

#[derive(Default)]
struct Observed {
    writes: Vec<Vec<u8>>,
    flushed: usize,
    blocked: bool,
    fail: bool,
    waker: Option<Waker>,
}
#[derive(Clone, Default)]
struct Writer(Arc<SyncMutex<Observed>>);
impl tokio::io::AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().writes.push(input.to_vec());
        Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        if state.blocked {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if state.fail {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        state.flushed += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn parts() -> ClientNetStackParts {
    NetStack::start_client(
        NetStackConfig {
            mtu: 65535,
            ..Default::default()
        },
        ClientConfig {
            prefixes: [
                Some(ClientPrefix {
                    address: "192.0.2.2".parse().unwrap(),
                    prefix_len: 32,
                }),
                Some(ClientPrefix {
                    address: "fd00::2".parse().unwrap(),
                    prefix_len: 128,
                }),
            ],
            receive_packet_limit: MAX_RECEIVE_PACKET_SIZE,
            path_mtu_discovery: true,
        },
    )
    .unwrap()
}
fn packet(id: u8, length: usize, ipv6: bool) -> Packet {
    let (source, destination) = if ipv6 {
        ("fd00::2", "fd00::3")
    } else {
        ("192.0.2.2", "198.51.100.1")
    };
    let mut raw = Vec::new();
    encode_udp_packet_into(
        &UdpDatagram::new(
            SocketAddr::new(source.parse().unwrap(), 40000 + u16::from(id)),
            SocketAddr::new(destination.parse().unwrap(), 50000 + u16::from(id)),
            Bytes::from(vec![id; length]),
        ),
        65535,
        &mut raw,
    )
    .unwrap();
    Packet::new(raw)
}
fn decoded(writes: &[Vec<u8>]) -> Vec<Vec<Bytes>> {
    writes
        .iter()
        .map(|wire| {
            let mut decoder = codec::CapsuleDecoder::new(MAX_RECEIVE_PACKET_SIZE);
            let mut input = wire.as_slice();
            let mut packets = Vec::new();
            while !input.is_empty() {
                let (consumed, capsule) = decoder.feed(input).unwrap();
                assert!(consumed > 0);
                input = &input[consumed..];
                if let Some(capsule) = capsule {
                    assert_eq!(capsule.kind, codec::DATAGRAM);
                    packets.push(capsule.value);
                }
            }
            decoder.finish().unwrap();
            packets
        })
        .collect()
}
fn assert_packets(actual: &[Bytes], expected: &[Packet]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        let original = parse_udp_packet_view(expected.data()).unwrap();
        let view = parse_udp_packet_view(actual).unwrap();
        assert_eq!(view.source, original.source);
        assert_eq!(view.destination, original.destination);
        assert_eq!(view.payload, original.payload);
        let offset = if actual[0] >> 4 == 4 { 8 } else { 7 };
        assert_eq!(actual[offset], expected.data()[offset] - 1);
        assert_eq!(expected.data()[offset], 64);
    }
}
async fn ready(input: &[Packet], fail_flush: bool) -> (io::Result<()>, Writer) {
    let parts = parts();
    let (tx, output) = mpsc::channel(input.len().max(1));
    for packet in input {
        tx.try_send(packet.clone()).unwrap();
    }
    drop(tx);
    let writer = Writer::default();
    writer.0.lock().unwrap().fail = fail_flush;
    let result = pump_h2_output(parts.packet_stream, output, writer.clone()).await;
    parts.control.stop().await;
    (result, writer)
}

#[tokio::test]
async fn ready_capsules_coalesce_and_flush_the_last_short_prefix_before_channel_end() {
    let input: Vec<_> = (1..=17).map(|id| packet(id, 32, id % 2 == 0)).collect();
    let (result, writer) = ready(&input, false).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    let state = writer.0.lock().unwrap();
    let groups = decoded(&state.writes);
    assert!(
        groups.len() < input.len(),
        "ready packets were still flushed one-by-one"
    );
    assert!(groups.iter().all(|group| group.len() <= 8));
    assert!(state.writes.iter().all(|wire| wire.len() <= 16 * 1024));
    assert_eq!(groups.last().unwrap().len(), 1);
    assert_eq!(state.flushed, groups.len());
    let actual: Vec<_> = groups.into_iter().flatten().collect();
    assert_packets(&actual, &input);
}

#[tokio::test]
async fn byte_spill_and_large_capsule_keep_order_and_apply_one_router_hop() {
    let input = [
        packet(1, 64, false),
        packet(2, 9000, true),
        packet(3, 9000, false),
        packet(4, 20000, true),
        packet(5, 64, false),
    ];
    let (result, writer) = ready(&input, false).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    let state = writer.0.lock().unwrap();
    let groups = decoded(&state.writes);
    assert!(groups.iter().any(|group| group.len() > 1));
    for (wire, group) in state.writes.iter().zip(&groups) {
        if wire.len() > 16 * 1024 {
            assert_eq!(group.len(), 1, "large capsule was aggregated or rejected");
            assert_eq!(
                parse_udp_packet_view(&group[0]).unwrap().payload.len(),
                20000
            );
        }
    }
    assert_eq!(state.flushed, groups.len());
    let actual: Vec<_> = groups.into_iter().flatten().collect();
    assert_packets(&actual, &input);
}

#[tokio::test]
async fn pending_flush_holds_the_next_batch_and_flush_error_precedes_channel_end() {
    let parts = parts();
    let (tx, output) = mpsc::channel(4);
    let first = packet(1, 32, false);
    let second = packet(2, 32, true);
    tx.try_send(first.clone()).unwrap();
    let writer = Writer::default();
    writer.0.lock().unwrap().blocked = true;
    let mut pump = Box::pin(pump_h2_output(parts.packet_stream, output, writer.clone()));
    assert!(futures_util::poll!(pump.as_mut()).is_pending());
    assert_eq!(
        writer.0.lock().unwrap().writes.len(),
        1,
        "single packet waited for a batch"
    );
    assert_eq!(writer.0.lock().unwrap().flushed, 0);
    tx.try_send(second.clone()).unwrap();
    let capacity = tx.capacity();
    assert!(futures_util::poll!(pump.as_mut()).is_pending());
    assert_eq!(
        tx.capacity(),
        capacity,
        "prefetched another batch while flush was pending"
    );
    assert_eq!(writer.0.lock().unwrap().writes.len(), 1);
    let wake = {
        let mut state = writer.0.lock().unwrap();
        state.blocked = false;
        state.waker.take()
    };
    if let Some(wake) = wake {
        wake.wake();
    }
    assert!(futures_util::poll!(pump.as_mut()).is_pending());
    drop(tx);
    assert_eq!(
        pump.as_mut().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    drop(pump);
    parts.control.stop().await;
    {
        let state = writer.0.lock().unwrap();
        let actual: Vec<_> = decoded(&state.writes).into_iter().flatten().collect();
        assert_packets(&actual, &[first.clone(), second]);
        assert_eq!(state.flushed, 2);
    }
    let (result, writer) = ready(&[first], true).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(writer.0.lock().unwrap().flushed, 0);
}

#[tokio::test]
async fn single_ready_poll_does_not_consume_a_later_udp_packet() {
    use futures_util::FutureExt;
    let mut parts = parts();
    let (tx, mut output) = mpsc::channel(1);
    assert!(
        next_h2_output(&mut parts.packet_stream, &mut output)
            .now_or_never()
            .is_none()
    );
    let expected = packet(1, 32, false);
    tx.try_send(expected.clone()).unwrap();
    assert_eq!(
        next_h2_output(&mut parts.packet_stream, &mut output)
            .await
            .unwrap(),
        expected
    );
    drop(tx);
    parts.control.stop().await;
}
