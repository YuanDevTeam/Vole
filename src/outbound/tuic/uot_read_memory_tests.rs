//! Real UoT codec and owned reader tests over in-memory duplex IO only.
//! The coalescing requirement deliberately fails the pass-through baseline;
//! it models the observed per-field read/lock amplification, not throughput.
use super::uot_receive_reader;
use crate::{
    dispatch::{DatagramTransport, DispatchError},
    outbound::uot::UotTransport,
    session::{Datagram, Destination},
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);
#[derive(Default)]
struct Counts {
    read_polls: AtomicUsize,
    nonempty_reads: AtomicUsize,
    read_bytes: AtomicUsize,
    reader_drops: AtomicUsize,
    io_drops: AtomicUsize,
}
struct CountingReader<R> {
    inner: R,
    counts: Arc<Counts>,
}
impl<R> Drop for CountingReader<R> {
    fn drop(&mut self) {
        self.counts.reader_drops.fetch_add(1, Ordering::Relaxed);
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        self.counts.read_polls.fetch_add(1, Ordering::Relaxed);
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let bytes = buf.filled().len() - before;
        self.counts.read_bytes.fetch_add(bytes, Ordering::Relaxed);
        if bytes != 0 {
            self.counts.nonempty_reads.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
struct OwnedMemoryIo {
    inner: DuplexStream,
    counts: Arc<Counts>,
}
impl Drop for OwnedMemoryIo {
    fn drop(&mut self) {
        self.counts.io_drops.fetch_add(1, Ordering::Relaxed);
    }
}
impl AsyncRead for OwnedMemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for OwnedMemoryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn association(
    parent: CancellationToken,
) -> (UotTransport, DuplexStream, TaskTracker, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let (io, peer) = tokio::io::duplex(32 * 1024);
    let io = OwnedMemoryIo {
        inner: io,
        counts: counts.clone(),
    };
    let (reader, writer) = tokio::io::split(io);
    let tracker = TaskTracker::new();
    let reader = CountingReader {
        inner: reader,
        counts: counts.clone(),
    };
    let transport = UotTransport::new(uot_receive_reader(reader), writer, 1200, parent, &tracker)
        .with_initial_deadline(tokio::time::Instant::now() + Duration::from_secs(10));
    (transport, peer, tracker, counts)
}
// An independent v2 datagram-mode response. Do not use Vole's encoder.
fn frame(port: u16, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len()).expect("bounded memory fixture");
    let mut wire = vec![0, 192, 0, 2, 10];
    wire.extend_from_slice(&port.to_be_bytes());
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}
fn assert_datagram(datagram: &Datagram, port: u16, payload: &[u8]) {
    assert_eq!(
        datagram.remote,
        Destination::Ip(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), port))
    );
    assert_eq!(datagram.payload.as_ref(), payload);
}
async fn finish(
    mut transport: UotTransport,
    peer: DuplexStream,
    tracker: TaskTracker,
    counts: &Counts,
) {
    let closed = tokio::time::timeout(TEST_TIMEOUT, transport.close()).await;
    drop(transport);
    drop(peer);
    tracker.close();
    let joined = tokio::time::timeout(TEST_TIMEOUT, tracker.wait()).await;
    assert!(joined.is_ok(), "actual UoT reader task did not join");
    assert!(tracker.is_empty());
    assert!(
        matches!(closed, Ok(Ok(()))),
        "memory transport close failed: {closed:?}"
    );
    assert_eq!(counts.reader_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counts.io_drops.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_factory_coalesces_already_available_response_frames() {
    let (mut transport, mut peer, tracker, counts) = association(CancellationToken::new());
    let payloads: Vec<_> = (0..8).map(|index| vec![0x40 + index; 1200]).collect();
    let wire: Vec<_> = payloads
        .iter()
        .enumerate()
        .flat_map(|(index, payload)| frame(5300 + index as u16, payload))
        .collect();
    // Queue the entire independent batch before the reader is first scheduled.
    let wrote = peer.write_all(&wire).await;
    let received = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut packets = Vec::new();
        for _ in &payloads {
            packets.push(transport.receive().await?);
        }
        Ok::<_, DispatchError>(packets)
    })
    .await;
    finish(transport, peer, tracker, &counts).await;
    wrote.expect("memory peer write");
    let received = received
        .expect("batch receive timed out")
        .expect("batch decode failed");
    for (index, packet) in received.iter().enumerate() {
        assert_datagram(packet, 5300 + index as u16, &payloads[index]);
    }
    assert_eq!(counts.read_bytes.load(Ordering::Relaxed), wire.len());
    let raw_reads = counts.nonempty_reads.load(Ordering::Relaxed);
    assert!(
        raw_reads <= payloads.len() / 2,
        "TUIC UoT factory amplified an already available batch into {raw_reads} nonempty raw reads for {} packets ({} total polls)",
        payloads.len(),
        counts.read_polls.load(Ordering::Relaxed)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_receive_cancellation_keeps_partial_frame_and_next_frame() {
    let (mut transport, mut peer, tracker, counts) = association(CancellationToken::new());
    let first_payload = vec![0x55; 1200];
    let second_payload = vec![0xa3; 777];
    let first = frame(5301, &first_payload);
    let second = frame(5302, &second_payload);
    let split = 9 + 301;
    let received = tokio::time::timeout(TEST_TIMEOUT, async {
        peer.write_all(&first[..split])
            .await
            .map_err(DispatchError::from)?;
        while counts.read_bytes.load(Ordering::Relaxed) < split {
            tokio::task::yield_now().await;
        }
        let was_pending = {
            let waker = futures_util::task::noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut waiting = transport.receive();
            std::future::Future::poll(waiting.as_mut(), &mut cx).is_pending()
        }; // Drop only the public receive future, not its owned parser.
        let mut remainder = first[split..].to_vec();
        remainder.extend_from_slice(&second);
        peer.write_all(&remainder)
            .await
            .map_err(DispatchError::from)?;
        let first = transport.receive().await?;
        let second = transport.receive().await?;
        Ok::<_, DispatchError>((was_pending, first, second))
    })
    .await;
    finish(transport, peer, tracker, &counts).await;
    let (was_pending, first_packet, second_packet) = received
        .expect("partial frame timed out")
        .expect("partial frame decode failed");
    assert!(was_pending);
    assert_datagram(&first_packet, 5301, &first_payload);
    assert_datagram(&second_packet, 5302, &second_payload);
    assert_eq!(
        counts.read_bytes.load(Ordering::Relaxed),
        first.len() + second.len()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_oversize_response_drains_before_next_valid_packet() {
    let (mut transport, mut peer, tracker, counts) = association(CancellationToken::new());
    let oversized = frame(5301, &vec![0x63; 4000]);
    let payload = vec![0x27; 411];
    let mut wire = oversized;
    wire.extend_from_slice(&frame(5302, &payload));
    let received = tokio::time::timeout(TEST_TIMEOUT, async {
        peer.write_all(&wire).await.map_err(DispatchError::from)?;
        transport.receive().await
    })
    .await;
    finish(transport, peer, tracker, &counts).await;
    let packet = received
        .expect("oversize drain timed out")
        .expect("oversize drain failed");
    assert_datagram(&packet, 5302, &payload);
    assert_eq!(counts.read_bytes.load(Ordering::Relaxed), wire.len());
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_close_joins_reader_before_releasing_complete_io() {
    let (mut transport, peer, tracker, counts) = association(CancellationToken::new());
    let closed = tokio::time::timeout(TEST_TIMEOUT, transport.close()).await;
    let readers_after_close = counts.reader_drops.load(Ordering::Relaxed);
    let io_after_close = counts.io_drops.load(Ordering::Relaxed);
    finish(transport, peer, tracker, &counts).await;
    assert!(matches!(closed, Ok(Ok(()))));
    assert_eq!(readers_after_close, 1);
    // The original writer half remains owned until transport Drop.
    assert_eq!(io_after_close, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_parent_cancel_joins_actual_reader_task() {
    let parent = CancellationToken::new();
    let (transport, peer, tracker, counts) = association(parent.clone());
    parent.cancel();
    tracker.close();
    let joined = tokio::time::timeout(TEST_TIMEOUT, tracker.wait()).await;
    let readers_after_cancel = counts.reader_drops.load(Ordering::Relaxed);
    finish(transport, peer, tracker, &counts).await;
    assert!(joined.is_ok());
    assert_eq!(readers_after_cancel, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_drop_joins_actual_reader_and_releases_both_io_halves() {
    let (transport, peer, tracker, counts) = association(CancellationToken::new());
    drop(transport);
    drop(peer);
    tracker.close();
    let joined = tokio::time::timeout(TEST_TIMEOUT, tracker.wait()).await;
    assert!(joined.is_ok());
    assert!(tracker.is_empty());
    assert_eq!(counts.reader_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counts.io_drops.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn tuic_uot_parent_cancel_discards_prefetched_frames_behind_full_response_queue() {
    let parent = CancellationToken::new();
    let raw_counts = Arc::new(Counts::default());
    let parsed_counts = Arc::new(Counts::default());
    let (io, mut peer) = tokio::io::duplex(32 * 1024);
    let io = OwnedMemoryIo {
        inner: io,
        counts: raw_counts.clone(),
    };
    let (reader, writer) = tokio::io::split(io);
    let raw_reader = CountingReader {
        inner: reader,
        counts: raw_counts.clone(),
    };
    // Observe both sides of the real production factory. The outer reader
    // measures bytes consumed by the real parser, not speculative prefetch.
    let parsed_reader = CountingReader {
        inner: uot_receive_reader(raw_reader),
        counts: parsed_counts.clone(),
    };
    let tracker = TaskTracker::new();
    let mut transport = UotTransport::new(parsed_reader, writer, 1200, parent.clone(), &tracker)
        .with_initial_deadline(tokio::time::Instant::now() + Duration::from_secs(10));
    let payloads: Vec<_> = (0..4).map(|index| vec![0x60 + index; 1200]).collect();
    let frames: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| frame(5400 + index as u16, payload))
        .collect();
    let wire: Vec<_> = frames
        .iter()
        .flat_map(|frame| frame.iter().copied())
        .collect();
    let parsed_two = frames[0].len() + frames[1].len();
    let ready = tokio::time::timeout(TEST_TIMEOUT, async {
        peer.write_all(&wire).await?;
        while parsed_counts.read_bytes.load(Ordering::Relaxed) < parsed_two {
            tokio::task::yield_now().await;
        }
        Ok::<_, io::Error>(())
    })
    .await;
    let parsed_before_cancel = parsed_counts.read_bytes.load(Ordering::Relaxed);
    let raw_before_cancel = raw_counts.read_bytes.load(Ordering::Relaxed);
    // No public receive has run. Two complete frames consumed by the real
    // read_loop mean the first occupies its one-response queue and the second
    // is waiting for admission. Raw bytes beyond both frames remain in the
    // factory's read-ahead buffer, including at least one further whole frame.
    parent.cancel();
    tracker.close();
    let joined = tokio::time::timeout(TEST_TIMEOUT, tracker.wait()).await;
    let parsed_after_join = parsed_counts.read_bytes.load(Ordering::Relaxed);
    let reader_drops_after_join = raw_counts.reader_drops.load(Ordering::Relaxed);
    let parsed_reader_drops_after_join = parsed_counts.reader_drops.load(Ordering::Relaxed);
    let io_drops_before_transport_drop = raw_counts.io_drops.load(Ordering::Relaxed);
    let after_cancel = tokio::time::timeout(TEST_TIMEOUT, transport.receive()).await;
    finish(transport, peer, tracker, &raw_counts).await;

    assert!(
        matches!(ready, Ok(Ok(()))),
        "real parser did not reach queue backpressure: {ready:?}"
    );
    assert_eq!(
        parsed_before_cancel, parsed_two,
        "the real response queue was not full before cancellation"
    );
    assert!(
        raw_before_cancel >= parsed_two + frames[2].len(),
        "the production reader had not prefetched a complete next frame"
    );
    assert!(raw_before_cancel <= wire.len());
    assert!(
        joined.is_ok(),
        "parent cancellation did not join the real reader"
    );
    assert_eq!(
        parsed_after_join, parsed_before_cancel,
        "cancellation consumed another prefetched frame"
    );
    assert_eq!(reader_drops_after_join, 1);
    assert_eq!(parsed_reader_drops_after_join, 1);
    assert_eq!(
        io_drops_before_transport_drop, 0,
        "the original writer half was released before transport Drop"
    );
    assert!(
        matches!(after_cancel, Ok(Err(_))),
        "a queued or prefetched packet escaped parent cancellation"
    );
    assert_eq!(parsed_counts.reader_drops.load(Ordering::Relaxed), 1);
    assert_eq!(raw_counts.reader_drops.load(Ordering::Relaxed), 1);
    assert_eq!(raw_counts.io_drops.load(Ordering::Relaxed), 1);
}
