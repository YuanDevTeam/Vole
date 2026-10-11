//! Single-connection, bounded public DatagramTransport to AsyncUdpSocket adapter.

mod runtime;
pub(crate) use runtime::OwnedRuntime;

/// Congestion algorithms used by the TrustTunnel and MASQUE consumers.
pub mod congestion;
mod congestion_factory;
pub use congestion_factory::congestion_controller;

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
        let can_receive = shared.state.lock().unwrap().incoming.len() < QUEUE_LIMIT;
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = shared.changed.notified() => {},
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
        self.0.writer.register(cx.waker());
        let state = self.0.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        if state.outgoing.len() < QUEUE_LIMIT {
            Poll::Ready(Ok(()))
        } else {
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
        self.shared.reader.register(cx.waker());
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        let Some(payload) = state.incoming.front() else {
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
