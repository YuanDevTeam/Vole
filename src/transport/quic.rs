//! Single-connection, bounded public DatagramTransport to AsyncUdpSocket adapter.

mod runtime;
pub(crate) use runtime::OwnedRuntime;

mod policy;
pub(crate) use policy::datagram_payload_limit;
pub use policy::{RECEIVE_WINDOW_POLICY, ReceiveWindowPolicy, configure_receive_windows};

use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub const QUEUE_LIMIT: usize = 32;
pub const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub sent: usize,
    pub received: usize,
    pub rejected_source: usize,
    pub rejected_oversize: usize,
    pub dropped_full: usize,
    pub peak_outgoing: usize,
    pub peak_incoming: usize,
}

#[derive(Default)]
struct State {
    incoming: VecDeque<Bytes>,
    outgoing: VecDeque<Bytes>,
    closed: bool,
    error: Option<io::ErrorKind>,
    stats: Stats,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Notify,
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl Shared {
    fn finish(&self, error: Option<io::ErrorKind>) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.error = state.error.or(error);
        state.incoming.clear();
        state.outgoing.clear();
        drop(state);
        self.reader.wake();
        self.writer.wake();
    }
}

/// One QUIC connection to one logical peer; no implicit socket creation or DNS.
pub struct DatagramSocket {
    peer: SocketAddr,
    budget: DatagramBudget,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for DatagramSocket {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("ControlledDatagramSocket")
            .finish_non_exhaustive()
    }
}

impl DatagramSocket {
    /// The endpoint must configure its QUIC MTU no larger than this budget.
    pub fn budget(&self) -> DatagramBudget {
        self.budget
    }

    pub fn stats(&self) -> Stats {
        self.shared.state.lock().unwrap().stats
    }

    /// Waits for previously enqueued packets to pass the controlled transport.
    /// This is local IO progress, not acknowledgement by the QUIC peer.
    pub(crate) fn poll_transmitted(
        &self,
        cx: &mut Context<'_>,
        count: usize,
    ) -> Poll<io::Result<()>> {
        let state = self.shared.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        if state.stats.sent >= count {
            Poll::Ready(Ok(()))
        } else {
            // Progress is published under the same lock, so register only
            // the blocked operation without a gap for a lost notification.
            self.shared.writer.register(cx.waker());
            Poll::Pending
        }
    }
}

pub struct DatagramDriver {
    shared: Arc<Shared>,
    cancel: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl DatagramDriver {
    pub async fn stop(mut self) -> io::Result<()> {
        self.join().await
    }

    /// Cancellation-safe join for an owner which retains this driver during
    /// a retiring-path grace period. A cancelled join can be awaited again.
    pub(crate) async fn join(&mut self) -> io::Result<()> {
        self.cancel.cancel();
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let result = task.await;
        self.task.take();
        result.map_err(|_| io::Error::from(io::ErrorKind::Other))?
    }
}

impl Drop for DatagramDriver {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.shared.finish(None);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub fn attach(
    transport: Box<dyn DatagramTransport>,
    peer: SocketAddr,
    budget: DatagramBudget,
) -> io::Result<(Arc<DatagramSocket>, DatagramDriver)> {
    attach_mapped(transport, peer, peer, budget)
}

/// Keep one logical QUIC peer while this transport owns exactly one physical
/// endpoint. Each hop uses a fresh Vole transport; no direct socket creation.
pub fn attach_mapped(
    mut transport: Box<dyn DatagramTransport>,
    logical_peer: SocketAddr,
    physical_peer: SocketAddr,
    budget: DatagramBudget,
) -> io::Result<(Arc<DatagramSocket>, DatagramDriver)> {
    if [logical_peer, physical_peer]
        .iter()
        .any(|peer| peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let budget = budget.intersect(transport.payload_budget(&Destination::Ip(physical_peer)));
    budget.quic_payload_limit()?;
    let shared = Arc::new(Shared::default());
    let socket = Arc::new(DatagramSocket {
        peer: logical_peer,
        budget,
        shared: shared.clone(),
    });
    let cancel = CancellationToken::new();
    let task_shared = shared.clone();
    let task_cancel = cancel.clone();
    let task = crate::resources::observation::spawn(async move {
        let result = drive(
            &mut *transport,
            physical_peer,
            budget,
            &task_shared,
            &task_cancel,
        )
        .await;
        task_shared.finish(result.as_ref().err().map(io::Error::kind));
        // The owned upstream must not hold synchronous Stop indefinitely.
        let closed = tokio::time::timeout(CLOSE_TIMEOUT, transport.close()).await;
        drop(transport);
        result?;
        closed
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map_err(dispatch_error)
    });
    Ok((
        socket,
        DatagramDriver {
            shared,
            cancel,
            task: Some(task),
        },
    ))
}

async fn drive(
    transport: &mut dyn DatagramTransport,
    peer: SocketAddr,
    budget: DatagramBudget,
    shared: &Shared,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let mut has_sent = false;
    loop {
        let (can_receive, can_send) = {
            let state = shared.state.lock().unwrap();
            (
                state.incoming.len() < QUEUE_LIMIT,
                !state.outgoing.is_empty(),
            )
        };
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = shared.changed.notified() => {},
            // Notify permits coalesce. A producer may have queued several
            // packets before this owner runs, so queued TX is itself ready.
            _ = std::future::ready(()), if can_send => {},
            received = transport.receive(), if has_sent && can_receive => {
                let datagram = received.map_err(dispatch_error)?;
                let mut state = shared.state.lock().unwrap();
                if datagram.remote != Destination::Ip(peer) {
                    state.stats.rejected_source += 1;
                } else if datagram.payload.len() > usize::from(budget.receive()) {
                    state.stats.rejected_oversize += 1;
                } else if state.incoming.len() == QUEUE_LIMIT {
                    state.stats.dropped_full += 1;
                } else {
                    state.incoming.push_back(datagram.payload);
                    state.stats.received += 1;
                    state.stats.peak_incoming = state.stats.peak_incoming.max(state.incoming.len());
                    crate::resources::observation::observe_queue(
                        crate::resources::observation::QueueKind::QuicIncoming,
                        state.incoming.len(),
                        QUEUE_LIMIT,
                    );
                    drop(state);
                    shared.reader.wake();
                }
            }
        }
        let payload = shared.state.lock().unwrap().outgoing.pop_front();
        if let Some(payload) = payload {
            shared.writer.wake();
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                sent = transport.send(Datagram { remote: Destination::Ip(peer), payload, sniffed_domain: None }) => sent.map_err(dispatch_error)?,
            }
            has_sent = true;
            let mut state = shared.state.lock().unwrap();
            state.stats.sent += 1;
            shared.writer.wake();
            if !state.outgoing.is_empty() {
                shared.changed.notify_one();
            }
        }
    }
}

fn dispatch_error(error: DispatchError) -> io::Error {
    match error {
        DispatchError::NotAllowed => io::ErrorKind::PermissionDenied,
        DispatchError::TimedOut => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::ConnectionAborted,
    }
    .into()
}

struct PacketPoller(Arc<Shared>);

impl std::fmt::Debug for PacketPoller {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("PacketPoller")
    }
}

impl UdpPoller for PacketPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let state = self.0.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        if state.outgoing.len() < QUEUE_LIMIT {
            Poll::Ready(Ok(()))
        } else {
            self.0.writer.register(cx.waker());
            Poll::Pending
        }
    }
}

impl AsyncUdpSocket for DatagramSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PacketPoller(self.shared.clone()))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.peer
            || transmit.contents.len() > usize::from(self.budget.transmit())
            || transmit.segment_size.is_some()
            || transmit.src_ip.is_some()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into());
        }
        if state.outgoing.len() == QUEUE_LIMIT {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state
            .outgoing
            .push_back(Bytes::copy_from_slice(transmit.contents));
        state.stats.peak_outgoing = state.stats.peak_outgoing.max(state.outgoing.len());
        crate::resources::observation::observe_queue(
            crate::resources::observation::QueueKind::QuicOutgoing,
            state.outgoing.len(),
            QUEUE_LIMIT,
        );
        drop(state);
        self.shared.changed.notify_one();
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        let Some(payload) = state.incoming.front() else {
            self.shared.reader.register(cx.waker());
            return Poll::Pending;
        };
        if buffers.is_empty() || meta.is_empty() || buffers[0].len() < payload.len() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        buffers[0][..payload.len()].copy_from_slice(payload);
        meta[0] = quinn::udp::RecvMeta {
            addr: self.peer,
            len: payload.len(),
            stride: payload.len(),
            ecn: None,
            dst_ip: None,
        };
        state.incoming.pop_front();
        // Resume the single transport owner when the consumer frees capacity.
        self.shared.changed.notify_one();
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Logical socket metadata only. Vole's public datagram transport owns
        // physical sockets and intentionally does not expose their bound ports.
        Ok(if self.peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap())
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Sink {
        sent: Arc<AtomicUsize>,
        changed: Arc<Notify>,
    }
    #[async_trait::async_trait]
    impl DatagramTransport for Sink {
        async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
            self.sent.fetch_add(1, Ordering::AcqRel);
            self.changed.notify_one();
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }
    #[tokio::test]
    async fn quic_memory_coalesced_notifications_drain_all_queued_packets_without_rx() {
        let sent = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(Notify::new());
        let peer = "192.0.2.1:443".parse().unwrap();
        let (socket, driver) = attach(
            Box::new(Sink {
                sent: sent.clone(),
                changed: changed.clone(),
            }),
            peer,
            DatagramBudget::new(1400, 1400),
        )
        .unwrap();
        // No await until all notifications have coalesced. The peer never
        // replies, so queued output must itself keep the owner runnable.
        for _ in 0..16 {
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: b"packet",
                    segment_size: None,
                    src_ip: None,
                })
                .unwrap();
        }
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while sent.load(Ordering::Acquire) < 16 {
                changed.notified().await;
            }
        })
        .await;
        driver.stop().await.unwrap();
        assert!(result.is_ok());
        assert_eq!(sent.load(Ordering::Acquire), 16);
    }
}

#[cfg(test)]
mod pending_waker_tests {
    use super::*;
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
        time::Duration,
    };
    use tokio::sync::{Semaphore, mpsc};

    #[derive(Default)]
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl Count {
        fn get(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }
    struct Carrier {
        input: mpsc::Receiver<Datagram>,
        credit: Arc<Semaphore>,
        starts: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl DatagramTransport for Carrier {
        async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
            self.starts.fetch_add(1, Ordering::Relaxed);
            self.credit
                .acquire()
                .await
                .map_err(|_| DispatchError::ConnectionRefused)?
                .forget();
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.input
                .recv()
                .await
                .ok_or(DispatchError::ConnectionRefused)
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    struct Fixture {
        socket: Arc<DatagramSocket>,
        driver: DatagramDriver,
        input: mpsc::Sender<Datagram>,
        credit: Arc<Semaphore>,
        starts: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
        peer: SocketAddr,
    }
    fn fixture(gated: bool) -> io::Result<Fixture> {
        let (input, receive) = mpsc::channel(64);
        let credit = Arc::new(Semaphore::new(if gated { 0 } else { 64 }));
        let starts = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let peer = "192.0.2.1:443".parse().unwrap();
        let (socket, driver) = attach(
            Box::new(Carrier {
                input: receive,
                credit: credit.clone(),
                starts: starts.clone(),
                closed: closed.clone(),
            }),
            peer,
            DatagramBudget::new(1400, 1400),
        )?;
        Ok(Fixture {
            socket,
            driver,
            input,
            credit,
            starts,
            closed,
            peer,
        })
    }
    fn send(fixture: &Fixture) -> io::Result<()> {
        fixture.socket.try_send(&quinn::udp::Transmit {
            destination: fixture.peer,
            ecn: None,
            contents: b"outbound",
            segment_size: None,
            src_ip: None,
        })
    }
    fn inject(fixture: &Fixture, payload: &'static [u8]) -> io::Result<()> {
        fixture
            .input
            .try_send(Datagram {
                remote: Destination::Ip(fixture.peer),
                payload: Bytes::from_static(payload),
                sniffed_domain: None,
            })
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
    async fn wait_for(mut condition: impl FnMut() -> bool) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut.into())
    }
    fn ready<T>(poll: Poll<io::Result<T>>) -> io::Result<T> {
        match poll {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    // These three RED cases exercise the real attached carrier and owner. No
    // setter manufactures queue/credit/readiness, and no AtomicWaker is taken
    // or cleared by the assertion. Stop is awaited before each failing assert.
    #[tokio::test]
    async fn quic_memory_ready_receive_does_not_register_for_next_packet() {
        let fixture = fixture(false).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let result = async {
            send(&fixture)?;
            wait_for(|| fixture.socket.stats().sent == 1).await?;
            inject(&fixture, b"first")?;
            wait_for(|| fixture.socket.stats().received == 1).await?;
            let mut bytes = [0; 1400];
            let mut meta = [quinn::udp::RecvMeta::default()];
            let received = ready(fixture.socket.poll_recv(
                &mut Context::from_waker(&waker),
                &mut [IoSliceMut::new(&mut bytes)],
                &mut meta,
            ))?;
            let first = bytes[..meta[0].len].to_vec();
            inject(&fixture, b"second")?;
            wait_for(|| fixture.socket.stats().received == 2).await?;
            Ok::<_, io::Error>((received, first, count.get()))
        }
        .await;
        fixture.driver.stop().await.unwrap();
        assert_eq!(fixture.closed.load(Ordering::Relaxed), 1);
        let (received, payload, wakes) = result.unwrap();
        assert_eq!(received, 1);
        assert_eq!(payload, b"first");
        assert_eq!(
            wakes, 0,
            "Ready receive retained a registration for later ingress"
        );
    }
    #[tokio::test]
    async fn quic_memory_ready_writable_does_not_register_for_later_send() {
        let fixture = fixture(false).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mut poller = fixture.socket.clone().create_io_poller();
        let result = async {
            ready(
                poller
                    .as_mut()
                    .poll_writable(&mut Context::from_waker(&waker)),
            )?;
            send(&fixture)?;
            wait_for(|| fixture.socket.stats().sent == 1).await?;
            Ok::<_, io::Error>(count.get())
        }
        .await;
        fixture.driver.stop().await.unwrap();
        assert_eq!(fixture.closed.load(Ordering::Relaxed), 1);
        assert_eq!(
            result.unwrap(),
            0,
            "Ready writable retained a registration for later egress"
        );
    }
    #[tokio::test]
    async fn quic_memory_ready_transmitted_does_not_register_for_later_send() {
        let fixture = fixture(false).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let result = async {
            send(&fixture)?;
            wait_for(|| fixture.socket.stats().sent == 1).await?;
            ready(
                fixture
                    .socket
                    .poll_transmitted(&mut Context::from_waker(&waker), 1),
            )?;
            send(&fixture)?;
            wait_for(|| fixture.socket.stats().sent == 2).await?;
            Ok::<_, io::Error>(count.get())
        }
        .await;
        fixture.driver.stop().await.unwrap();
        assert_eq!(fixture.closed.load(Ordering::Relaxed), 1);
        assert_eq!(
            result.unwrap(),
            0,
            "Ready transmission barrier retained a registration"
        );
    }
    // Cancellation drops only the waiting future; the carrier/driver stays
    // owned. A subsequent Pending caller gets the next real progress wake.
    #[tokio::test]
    async fn quic_memory_cancelled_receive_wait_replaced_by_pending_reader_is_woken() {
        let fixture = fixture(false).unwrap();
        let cancelled = Arc::new(Count::default());
        let count = Arc::new(Count::default());
        let first_waker = Waker::from(cancelled);
        let waker = Waker::from(count.clone());
        let result = async {
            send(&fixture)?;
            wait_for(|| fixture.socket.stats().sent == 1).await?;
            let mut bytes = [0; 1400];
            let mut meta = [quinn::udp::RecvMeta::default()];
            let mut wait = Box::pin(std::future::poll_fn(|cx| {
                fixture
                    .socket
                    .poll_recv(cx, &mut [IoSliceMut::new(&mut bytes)], &mut meta)
            }));
            let first_pending = wait
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending();
            drop(wait);
            let pending = fixture
                .socket
                .poll_recv(
                    &mut Context::from_waker(&waker),
                    &mut [IoSliceMut::new(&mut bytes)],
                    &mut meta,
                )
                .is_pending();
            inject(&fixture, b"resumed")?;
            wait_for(|| count.get() > 0).await?;
            let delivered = ready(fixture.socket.poll_recv(
                &mut Context::from_waker(&waker),
                &mut [IoSliceMut::new(&mut bytes)],
                &mut meta,
            ))?;
            Ok::<_, io::Error>((
                first_pending,
                pending,
                delivered,
                bytes[..meta[0].len].to_vec(),
            ))
        }
        .await;
        fixture.driver.stop().await.unwrap();
        assert_eq!(fixture.closed.load(Ordering::Relaxed), 1);
        let (first_pending, pending, delivered, payload) = result.unwrap();
        assert!(first_pending && pending);
        assert_eq!(delivered, 1);
        assert_eq!(payload, b"resumed");
    }
    #[tokio::test]
    async fn quic_memory_pending_writable_wakes_on_real_queue_capacity() {
        let fixture = fixture(true).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mut poller = fixture.socket.clone().create_io_poller();
        let result = async {
            send(&fixture)?;
            wait_for(|| fixture.starts.load(Ordering::Relaxed) == 1).await?;
            for _ in 0..QUEUE_LIMIT {
                send(&fixture)?;
            }
            let overflow = send(&fixture).err().map(|error| error.kind());
            let pending = poller
                .as_mut()
                .poll_writable(&mut Context::from_waker(&waker))
                .is_pending();
            fixture.credit.add_permits(1);
            wait_for(|| fixture.starts.load(Ordering::Relaxed) >= 2 && count.get() > 0).await?;
            ready(
                poller
                    .as_mut()
                    .poll_writable(&mut Context::from_waker(&waker)),
            )?;
            Ok::<_, io::Error>((overflow, pending))
        }
        .await;
        fixture.driver.stop().await.unwrap();
        assert_eq!(fixture.closed.load(Ordering::Relaxed), 1);
        let (overflow, pending) = result.unwrap();
        assert_eq!(overflow, Some(io::ErrorKind::WouldBlock));
        assert!(pending);
    }
    #[tokio::test]
    async fn quic_memory_pending_transmission_wakes_on_real_send_completion() {
        let fixture = fixture(true).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let result = async {
            send(&fixture)?;
            wait_for(|| fixture.starts.load(Ordering::Relaxed) == 1).await?;
            let pending = fixture
                .socket
                .poll_transmitted(&mut Context::from_waker(&waker), 1)
                .is_pending();
            fixture.credit.add_permits(1);
            wait_for(|| fixture.socket.stats().sent == 1 && count.get() > 0).await?;
            ready(
                fixture
                    .socket
                    .poll_transmitted(&mut Context::from_waker(&waker), 1),
            )?;
            Ok::<_, io::Error>(pending)
        }
        .await;
        fixture.driver.stop().await.unwrap();
        assert_eq!(fixture.closed.load(Ordering::Relaxed), 1);
        assert!(result.unwrap());
    }
}
