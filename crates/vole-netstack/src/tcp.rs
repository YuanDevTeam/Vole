use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Read as _},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use futures_util::task::AtomicWaker;
use memmap2::MmapMut;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::ClientConfig;

pub(crate) struct ConnectRequest {
    pub(crate) destination: SocketAddr,
    pub(crate) deadline: Instant,
    pub(crate) cancellation: CancellationToken,
    pub(crate) response: oneshot::Sender<std::io::Result<TcpStream>>,
}

pub(crate) struct InitialMtuRequest {
    pub(crate) mtu: usize,
    pub(crate) deadline: Instant,
    pub(crate) response: oneshot::Sender<std::io::Result<()>>,
}

pub(crate) enum ClientRequest {
    Connect(ConnectRequest),
    InitialMtu(InitialMtuRequest),
}

struct ConnectGuard {
    cancellation: CancellationToken,
    notify: Arc<Notify>,
    armed: bool,
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
            self.notify.notify_one();
        }
    }
}

/// Active TCP connections driven entirely by the stack's raw-IP endpoints.
#[derive(Clone)]
pub struct TcpConnector {
    pub(crate) sender: mpsc::Sender<ClientRequest>,
    pub(crate) cancellation: CancellationToken,
    pub(crate) notify: Arc<Notify>,
    pub(crate) addresses: ClientConfig,
}

impl TcpConnector {
    /// Reduces the initial transmit MTU to a known packet-transport budget.
    ///
    /// This must complete before the first TCP connection. Receive packet
    /// limits and source prefixes remain unchanged. Admission and completion
    /// share the supplied deadline, and Stop never waits on this command.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an increase or invalid family MTU,
    /// `AlreadyExists` once TCP output or a flow exists, `TimedOut` at the
    /// deadline, and `ConnectionAborted` when the stack stops.
    pub async fn set_initial_mtu(&self, mtu: usize, deadline: Instant) -> std::io::Result<()> {
        if Instant::now() >= deadline {
            return Err(connect_timeout());
        }
        let (response, received) = oneshot::channel();
        let request = ClientRequest::InitialMtu(InitialMtuRequest {
            mtu,
            deadline,
            response,
        });
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(connect_stopped()),
            () = tokio::time::sleep_until(deadline) => return Err(connect_timeout()),
            result = self.sender.send(request) => result.map_err(|_| connect_stopped())?,
        }
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(connect_stopped()),
            () = tokio::time::sleep_until(deadline) => Err(connect_timeout()),
            result = received => result.unwrap_or_else(|_| Err(connect_stopped())),
        }
    }

    /// Connects to an IP endpoint and returns only after TCP is established.
    ///
    /// Queue admission and handshake share the supplied absolute deadline.
    /// Dropping this future cancels its pending request and socket; no background
    /// connect task survives the caller. The stack performs no DNS or host I/O.
    ///
    /// # Errors
    ///
    /// Returns `AddrNotAvailable` for an unconfigured address family,
    /// `InvalidInput` for a non-unicast/zero-port peer, `TimedOut` at the
    /// deadline, or an I/O error when TCP fails or the stack stops.
    pub async fn connect(
        &self,
        mut destination: SocketAddr,
        deadline: Instant,
    ) -> std::io::Result<TcpStream> {
        if let std::net::IpAddr::V6(ip) = destination.ip()
            && let Some(ip) = ip.to_ipv4_mapped()
        {
            destination = SocketAddr::new(ip.into(), destination.port());
        }
        let invalid_ip = match destination.ip() {
            std::net::IpAddr::V4(ip) => {
                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
            }
            std::net::IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
        };
        if invalid_ip || destination.port() == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid active TCP peer",
            ));
        }
        self.addresses.source_for(destination.ip())?;
        if Instant::now() >= deadline {
            return Err(connect_timeout());
        }
        let cancellation = CancellationToken::new();
        let mut guard = ConnectGuard {
            cancellation: cancellation.clone(),
            notify: self.notify.clone(),
            armed: true,
        };
        let (response, received) = oneshot::channel();
        let request = ConnectRequest {
            destination,
            deadline,
            cancellation,
            response,
        };
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(connect_stopped()),
            () = tokio::time::sleep_until(deadline) => return Err(connect_timeout()),
            result = self.sender.send(ClientRequest::Connect(request)) => result.map_err(|_| connect_stopped())?,
        }
        let result = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(connect_stopped()),
            () = tokio::time::sleep_until(deadline) => Err(connect_timeout()),
            result = received => result.unwrap_or_else(|_| Err(connect_stopped())),
        };
        if result.is_ok() {
            guard.armed = false;
        }
        result
    }
}

pub(crate) fn connect_stopped() -> Error {
    Error::new(
        ErrorKind::ConnectionAborted,
        "netstack is stopping or stopped",
    )
}

pub(crate) fn connect_timeout() -> Error {
    Error::new(ErrorKind::TimedOut, "netstack TCP connect deadline elapsed")
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowKey {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
}

#[cfg(any(unix, test))]
const MAPPED_TX_MINIMUM: usize = 64 * 1024;
const MAPPED_IDLE_SLOTS: usize = 4;

type MapSlots = [Option<QueueMapping>; MAPPED_IDLE_SLOTS];

struct QueueMapping {
    bytes: MmapMut,
    // Fields drop in declaration order: this marker ends only after the real
    // safe memmap2 owner has run its unmap Drop.
    #[cfg(test)]
    lifetime: Arc<()>,
}

impl QueueMapping {
    #[cfg(unix)]
    fn new(capacity: usize) -> std::io::Result<Self> {
        if capacity == 0 || capacity > isize::MAX.unsigned_abs() {
            return Err(ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            bytes: MmapMut::map_anon(capacity)?,
            #[cfg(test)]
            lifetime: Arc::new(()),
        })
    }

    #[cfg(not(unix))]
    fn new(_capacity: usize) -> std::io::Result<Self> {
        // Keep non-Unix queues on their existing bounded Vec path. Do not
        // invoke another platform's anonymous-mapping failure path here.
        Err(ErrorKind::Unsupported.into())
    }

    fn capacity(&self) -> usize {
        self.bytes.len()
    }
}

struct MappedByteRing {
    mapping: QueueMapping,
    head: usize,
    length: usize,
}

impl MappedByteRing {
    fn new(mapping: QueueMapping) -> Self {
        Self {
            mapping,
            head: 0,
            length: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.mapping.capacity()
    }
    fn is_empty(&self) -> bool {
        self.length == 0
    }

    fn write(&mut self, source: &[u8]) -> usize {
        let capacity = self.capacity();
        let count = source.len().min(capacity - self.length);
        if count == 0 {
            return 0;
        }
        let tail = (self.head + self.length) % capacity;
        let first = count.min(capacity - tail);
        self.mapping.bytes[tail..tail + first].copy_from_slice(&source[..first]);
        if first < count {
            self.mapping.bytes[..count - first].copy_from_slice(&source[first..count]);
        }
        self.length += count;
        count
    }

    fn read(&mut self, target: &mut [u8]) -> usize {
        // Match the original VecDeque Read contract: one contiguous prefix is
        // valid progress, and a caller can repeat for the wrapped suffix.
        let count = target
            .len()
            .min(self.length)
            .min(self.capacity() - self.head);
        if count == 0 {
            return 0;
        }
        target[..count].copy_from_slice(&self.mapping.bytes[self.head..self.head + count]);
        self.head = (self.head + count) % self.capacity();
        self.length -= count;
        if self.length == 0 {
            self.head = 0;
        }
        count
    }
}

/// Driver-owned idle anonymous mappings. The byte bound counts requested map
/// lengths; OS page padding and fixed Arc/mutex/slot metadata are separate.
/// No cache entry can contain live bytes or own a stream/Driver strongly.
pub(crate) struct MapCache {
    state: Mutex<MapState>,
    capacity: usize,
    closed: AtomicBool,
    #[cfg(test)]
    fail_next_map: AtomicBool,
    #[cfg(test)]
    map_attempts: std::sync::atomic::AtomicUsize,
}

struct MapState {
    mappings: MapSlots,
    retained: usize,
}

impl MapCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(MapState {
                mappings: std::array::from_fn(|_| None),
                retained: 0,
            }),
            capacity,
            closed: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_map: AtomicBool::new(false),
            #[cfg(test)]
            map_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn take(&self, capacity: usize) -> Option<MappedByteRing> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.try_lock().ok()?;
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let index = state.mappings.iter().position(|mapping| {
            mapping
                .as_ref()
                .is_some_and(|mapping| mapping.capacity() == capacity)
        })?;
        let mapping = state.mappings[index].take()?;
        state.retained -= mapping.capacity();
        Some(MappedByteRing::new(mapping))
    }

    fn acquire(&self, capacity: usize) -> Option<MappedByteRing> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        if let Some(ring) = self.take(capacity) {
            return Some(ring);
        }
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        #[cfg(test)]
        {
            self.map_attempts.fetch_add(1, Ordering::Relaxed);
            if self.fail_next_map.swap(false, Ordering::AcqRel) {
                return None;
            }
        }
        QueueMapping::new(capacity).ok().map(MappedByteRing::new)
    }

    fn put(&self, ring: MappedByteRing) -> Result<(), MappedByteRing> {
        let capacity = ring.capacity();
        if !ring.is_empty()
            || capacity == 0
            || capacity > self.capacity
            || self.closed.load(Ordering::Acquire)
        {
            return Err(ring);
        }
        let Ok(mut state) = self.state.try_lock() else {
            return Err(ring);
        };
        if self.closed.load(Ordering::Acquire) || state.retained > self.capacity - capacity {
            return Err(ring);
        }
        let Some(index) = state.mappings.iter().position(Option::is_none) else {
            return Err(ring);
        };
        state.retained += capacity;
        state.mappings[index] = Some(ring.mapping);
        Ok(())
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let retired: MapSlots = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.retained = 0;
            std::array::from_fn(|index| state.mappings[index].take())
        };
        drop(retired); // Actual unmap only after releasing cache metadata.
    }

    #[cfg(test)]
    pub(crate) fn retained_for_test(&self) -> usize {
        self.state.lock().unwrap().retained
    }
}

enum QueueStorage {
    Vector(VecDeque<u8>),
    Mapped(MappedByteRing),
}

struct QueueState {
    storage: QueueStorage,
    mapping_disabled: bool,
}

impl QueueState {
    fn len(&self) -> usize {
        match &self.storage {
            QueueStorage::Vector(bytes) => bytes.len(),
            QueueStorage::Mapped(ring) => ring.length,
        }
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn capacity(&self) -> usize {
        match &self.storage {
            QueueStorage::Vector(bytes) => bytes.capacity(),
            QueueStorage::Mapped(ring) => ring.capacity(),
        }
    }
    fn write(&mut self, source: &[u8], limit: usize) -> usize {
        match &mut self.storage {
            QueueStorage::Mapped(ring) => ring.write(source),
            QueueStorage::Vector(bytes) => {
                let count = source.len().min(limit - bytes.len());
                let needed = bytes.len() + count;
                if needed > bytes.capacity() {
                    let target = needed.max(bytes.capacity().saturating_mul(2)).min(limit);
                    bytes.reserve_exact(target - bytes.len());
                }
                bytes.extend(&source[..count]);
                count
            }
        }
    }
    fn read(&mut self, target: &mut [u8]) -> usize {
        match &mut self.storage {
            QueueStorage::Mapped(ring) => ring.read(target),
            QueueStorage::Vector(bytes) => bytes
                .read(target)
                .expect("reading an in-memory queue cannot fail"),
        }
    }
}

/// Default RX/small queues retain `VecDeque` backing. Large application TX and
/// explicitly opted-in application RX may return an empty mapping to their
/// independent Driver-owned cache without moving live bytes.
pub(crate) struct ByteQueue {
    bytes: Mutex<QueueState>,
    capacity: usize,
    map_cache: Option<Weak<MapCache>>,
    // Advisory only; authoritative FIN/flush checks still take the queue lock.
    nonempty_hint: Option<AtomicBool>,
}

impl ByteQueue {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: Mutex::new(QueueState {
                storage: QueueStorage::Vector(VecDeque::new()),
                mapping_disabled: false,
            }),
            capacity,
            map_cache: None,
            nonempty_hint: None,
        }
    }
    fn new_tx(capacity: usize) -> Self {
        Self {
            nonempty_hint: Some(AtomicBool::new(false)),
            ..Self::new(capacity)
        }
    }

    // Keep publication inside the same queue lock for both storage backends.
    fn publish_nonempty(&self, bytes: &MutexGuard<'_, QueueState>) {
        if let Some(hint) = &self.nonempty_hint {
            hint.store(!bytes.is_empty(), Ordering::Release);
        }
    }

    pub(crate) fn may_have_data(&self) -> bool {
        self.nonempty_hint
            .as_ref()
            .is_none_or(|hint| hint.load(Ordering::Acquire))
    }

    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(crate) fn write(&self, source: &[u8]) -> usize {
        let cache = self.map_cache.as_ref().and_then(Weak::upgrade);
        let mut bytes = self.lock();
        if !source.is_empty()
            && bytes.is_empty()
            && bytes.capacity() == 0
            && !bytes.mapping_disabled
            && self.map_cache.is_some()
        {
            let ring = cache
                .as_ref()
                .and_then(|cache| cache.acquire(self.capacity));
            if let Some(ring) = ring {
                bytes.storage = QueueStorage::Mapped(ring);
            } else {
                bytes.mapping_disabled = true;
            } // Original bounded Vec path remains live.
        }
        let count = bytes.write(source, self.capacity);
        self.publish_nonempty(&bytes);
        drop(bytes);
        drop(cache);
        count
    }
    pub(crate) fn read(&self, target: &mut [u8]) -> usize {
        let cache = self.map_cache.as_ref().and_then(Weak::upgrade);
        let mut bytes = self.lock();
        let count = bytes.read(target);
        let retired = if bytes.is_empty() && matches!(&bytes.storage, QueueStorage::Mapped(_)) {
            let QueueStorage::Mapped(ring) =
                std::mem::replace(&mut bytes.storage, QueueStorage::Vector(VecDeque::new()))
            else {
                unreachable!()
            };
            match &cache {
                Some(cache) => cache.put(ring).err(),
                None => Some(ring),
            }
        } else {
            None
        };
        self.publish_nonempty(&bytes);
        drop(bytes);
        drop(retired); // Rejected mapping unmaps outside both locks.
        count
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
    #[cfg(test)]
    pub(crate) fn mapped_lifetime_for_test(&self) -> Option<Weak<()>> {
        match &self.lock().storage {
            QueueStorage::Mapped(ring) => Some(Arc::downgrade(&ring.mapping.lifetime)),
            QueueStorage::Vector(_) => None,
        }
    }
}

pub(crate) struct TcpStreamHandle {
    pub(crate) app_recv: ByteQueue,
    pub(crate) app_send: ByteQueue,
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_waker: AtomicWaker,
    pub(crate) dropped: AtomicBool,
    pub(crate) socket_closed: AtomicBool,
    pub(crate) read_closed: AtomicBool,
    pub(crate) write_closed: AtomicBool,
    pub(crate) write_shutdown: AtomicBool,
    pub(crate) stopped: AtomicBool,
    pub(crate) driver_notify: Arc<Notify>,
}

impl TcpStreamHandle {
    pub(crate) fn with_rx_cache(self, cache: Weak<MapCache>) -> Self {
        #[cfg(unix)]
        {
            let mut handle = self;
            handle.app_recv.map_cache = Some(cache);
            // RX keeps its authoritative lock/read/waker behavior; it never
            // opts into the advisory application-TX nonempty hint.
            handle
        }
        #[cfg(not(unix))]
        {
            let _ = cache;
            self
        }
    }

    pub(crate) fn with_tx_cache(self, cache: Weak<MapCache>) -> Self {
        #[cfg(unix)]
        {
            let mut handle = self;
            if handle.app_send.capacity >= MAPPED_TX_MINIMUM {
                handle.app_send.map_cache = Some(cache);
            }
            handle
        }
        #[cfg(not(unix))]
        {
            let _ = cache;
            self
        }
    }

    pub(crate) fn new(
        app_recv_buffer: usize,
        app_send_buffer: usize,
        driver_notify: Arc<Notify>,
    ) -> Self {
        Self {
            app_recv: ByteQueue::new(app_recv_buffer),
            app_send: ByteQueue::new_tx(app_send_buffer),
            recv_waker: AtomicWaker::new(),
            send_waker: AtomicWaker::new(),
            dropped: AtomicBool::new(false),
            socket_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            driver_notify,
        }
    }

    pub(crate) fn wake_all(&self) {
        self.recv_waker.wake();
        self.send_waker.wake();
    }

    pub(crate) fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::Release);
        self.socket_closed.store(true, Ordering::Release);
        self.read_closed.store(true, Ordering::Release);
        self.write_closed.store(true, Ordering::Release);
        self.wake_all();
    }
}

/// One intercepted or actively established userspace TCP flow.
pub struct TcpStream {
    flow: FlowKey,
    pub(crate) handle: Arc<TcpStreamHandle>,
    #[cfg(test)]
    read_empty_probe: Option<Box<dyn FnMut(usize) + Send + Sync>>,
    #[cfg(test)]
    empty_reads: usize,
}

impl TcpStream {
    pub(crate) fn new(flow: FlowKey, handle: Arc<TcpStreamHandle>) -> Self {
        Self {
            flow,
            handle,
            #[cfg(test)]
            read_empty_probe: None,
            #[cfg(test)]
            empty_reads: 0,
        }
    }

    #[cfg(test)]
    fn after_empty_read(&mut self) {
        self.empty_reads += 1;
        if let Some(probe) = &mut self.read_empty_probe {
            probe(self.empty_reads);
        }
    }

    /// Intercepted application address, or local source of an active connection.
    #[must_use]
    pub const fn source_addr(&self) -> SocketAddr {
        self.flow.source
    }

    /// Original intercepted destination, or remote peer of an active connection.
    #[must_use]
    pub const fn destination_addr(&self) -> SocketAddr {
        self.flow.destination
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.handle.stopped.load(Ordering::Acquire)
    }

    fn notify_driver(&self) {
        self.handle.driver_notify.notify_one();
    }

    fn write_unavailable(&self) -> bool {
        self.handle.write_closed.load(Ordering::Acquire)
            || self.handle.socket_closed.load(Ordering::Acquire)
            || self.handle.write_shutdown.load(Ordering::Acquire)
            || self.handle.stopped.load(Ordering::Acquire)
    }

    fn read_ended_and_drained(&self) -> bool {
        // The driver can publish its final bytes and terminal flag after an
        // earlier read observed the queue empty. Observe publication first,
        // then recheck the actual queue before allowing that read to be EOF.
        (self.handle.read_closed.load(Ordering::Acquire)
            || self.handle.socket_closed.load(Ordering::Acquire)
            || self.handle.stopped.load(Ordering::Acquire))
            && self.handle.app_recv.is_empty()
    }
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpStream")
            .field("source_addr", &self.source_addr())
            .field("destination_addr", &self.destination_addr())
            .finish_non_exhaustive()
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.handle.dropped.store(true, Ordering::Release);
        self.handle.read_closed.store(true, Ordering::Release);
        self.handle.write_closed.store(true, Ordering::Release);
        self.handle.wake_all();
        self.notify_driver();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let target = buffer.initialize_unfilled();
        let count = this.handle.app_recv.read(target);
        if count > 0 {
            buffer.advance(count);
            this.notify_driver();
            return Poll::Ready(Ok(()));
        }

        #[cfg(test)]
        this.after_empty_read();
        if this.read_ended_and_drained() {
            return Poll::Ready(Ok(()));
        }

        this.handle.recv_waker.register(context.waker());
        let count = this.handle.app_recv.read(buffer.initialize_unfilled());
        #[cfg(test)]
        if count == 0 {
            this.after_empty_read();
        }
        if count > 0 {
            buffer.advance(count);
            this.notify_driver();
            Poll::Ready(Ok(()))
        } else if this.read_ended_and_drained() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_unavailable() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "netstack TCP write side is closed",
            )));
        }

        let count = self.handle.app_send.write(buffer);
        if count > 0 {
            self.notify_driver();
            return Poll::Ready(Ok(count));
        }

        self.handle.send_waker.register(context.waker());
        let count = self.handle.app_send.write(buffer);
        if count > 0 {
            self.notify_driver();
            Poll::Ready(Ok(count))
        } else if self.write_unavailable() {
            Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "netstack TCP write side is closed",
            )))
        } else {
            // The successful publication already notified the driver. Keep
            // the registered waker and double-check, without a new Mac wake.
            #[cfg(not(target_os = "macos"))]
            self.notify_driver();
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.handle.app_send.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if self.write_unavailable() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "netstack TCP write side closed before buffered data was flushed",
            )));
        }
        self.handle.send_waker.register(context.waker());
        if self.handle.app_send.is_empty() {
            Poll::Ready(Ok(()))
        } else if self.write_unavailable() {
            Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "netstack TCP write side closed before buffered data was flushed",
            )))
        } else {
            #[cfg(not(target_os = "macos"))]
            self.notify_driver();
            Poll::Pending
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush(context))?;
        self.handle.write_shutdown.store(true, Ordering::Release);
        self.notify_driver();
        Poll::Ready(Ok(()))
    }
}

/// Bounded async accept queue for intercepted TCP flows.
pub struct TcpListener {
    pub(crate) receiver: mpsc::Receiver<TcpStream>,
    pub(crate) cancellation: CancellationToken,
}

impl TcpListener {
    /// Returns `None` once the stack is stopping or has stopped.
    pub async fn accept(&mut self) -> Option<TcpStream> {
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => None,
            stream = self.receiver.recv() => stream,
        }
    }
}

#[cfg(test)]
#[path = "tcp_pending_notify_memory_tests.rs"]
mod pending_notify_memory_tests;

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::AtomicUsize,
        task::{Wake, Waker},
        time::Duration,
    };

    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum ReadEnd {
        PeerFin,
        SocketClosed,
        Stopped,
    }

    impl ReadEnd {
        fn publish(self, handle: &TcpStreamHandle) {
            match self {
                Self::PeerFin => handle.read_closed.store(true, Ordering::Release),
                Self::SocketClosed => handle.socket_closed.store(true, Ordering::Release),
                Self::Stopped => {
                    handle.mark_stopped();
                    return;
                }
            }
            handle.recv_waker.wake();
        }
    }

    struct ReadWake(AtomicUsize);
    impl Wake for ReadWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn assert_published_tail_precedes_eof(
        empty_probe: usize,
        ending: ReadEnd,
        rx_cache: Option<Arc<MapCache>>,
    ) {
        let mut handle = TcpStreamHandle::new(
            rx_cache.as_ref().map_or(1024, |cache| cache.capacity / 2),
            16,
            Arc::new(Notify::new()),
        );
        if let Some(cache) = &rx_cache {
            handle = handle.with_rx_cache(Arc::downgrade(cache));
        }
        let handle = Arc::new(handle);
        let mut stream = TcpStream::new(
            FlowKey {
                source: "192.0.2.1:12000".parse().unwrap(),
                destination: "198.51.100.1:443".parse().unwrap(),
            },
            handle.clone(),
        );
        // Publish exactly where the concurrent driver can deliver its final
        // bytes: after a consumer observed the real queue empty, before its
        // terminal-state decision. There is no global hook or scheduler race.
        let publisher = handle.clone();
        let expect_map = rx_cache.is_some();
        stream.read_empty_probe = Some(Box::new(move |probe| {
            if probe == empty_probe {
                assert_eq!(publisher.app_recv.write(&[0x5a; 730]), 730);
                assert_eq!(
                    publisher.app_recv.mapped_lifetime_for_test().is_some(),
                    expect_map
                );
                ending.publish(&publisher);
            }
        }));
        let notifications = Arc::new(ReadWake(AtomicUsize::new(0)));
        let waker = Waker::from(notifications.clone());
        let mut context = Context::from_waker(&waker);
        let mut bytes = [0; 1024];
        let mut buffer = ReadBuf::new(&mut bytes);
        let first = Pin::new(&mut stream).poll_read(&mut context, &mut buffer);
        if first.is_pending() {
            assert!(
                notifications.0.load(Ordering::Relaxed) > 0,
                "{ending:?}: registered consumer lost the final publication wake"
            );
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut context, &mut buffer),
                Poll::Ready(Ok(()))
            ));
        } else {
            assert!(matches!(first, Poll::Ready(Ok(()))));
        }
        assert_eq!(
            buffer.filled().len(),
            730,
            "{ending:?}: empty probe {empty_probe} returned EOF before its accepted tail"
        );
        assert!(buffer.filled().iter().all(|byte| *byte == 0x5a));
        assert!(handle.app_recv.is_empty());
        let mut final_byte = [0];
        let mut eof = ReadBuf::new(&mut final_byte);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut context, &mut eof),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(eof.filled(), []);
        if let Some(cache) = rx_cache {
            assert_eq!(cache.retained_for_test(), cache.capacity / 2);
            cache.close();
        }
    }

    #[test]
    fn tcp_read_publication_after_initial_empty_probe_drains_before_eof() {
        for ending in [ReadEnd::PeerFin, ReadEnd::SocketClosed, ReadEnd::Stopped] {
            assert_published_tail_precedes_eof(1, ending, None);
        }
    }

    #[test]
    fn tcp_read_publication_after_registered_empty_probe_drains_before_eof() {
        for ending in [ReadEnd::PeerFin, ReadEnd::SocketClosed, ReadEnd::Stopped] {
            assert_published_tail_precedes_eof(2, ending, None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn mapped_rx_publication_after_both_empty_probes_drains_before_eof() {
        for total in [112 * 1024, 128 * 1024] {
            for probe in [1, 2] {
                for ending in [ReadEnd::PeerFin, ReadEnd::SocketClosed, ReadEnd::Stopped] {
                    assert_published_tail_precedes_eof(
                        probe,
                        ending,
                        Some(Arc::new(MapCache::new(total))),
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn mapped_rx_empty_cache_is_bounded_and_independent_from_tx() {
        for (capacity, tx_total) in [(56 * 1024, 64 * 1024), (64 * 1024, 32 * 1024)] {
            assert_mapped_rx_empty_cache(capacity, tx_total);
        }
    }

    #[cfg(unix)]
    fn assert_mapped_rx_empty_cache(capacity: usize, tx_total: usize) {
        let rx = Arc::new(MapCache::new(2 * capacity));
        let tx = Arc::new(MapCache::new(tx_total));
        let queues: Vec<_> = (0..3)
            .map(|_| {
                let handle = TcpStreamHandle::new(capacity, tx_total / 2, Arc::new(Notify::new()))
                    .with_tx_cache(Arc::downgrade(&tx))
                    .with_rx_cache(Arc::downgrade(&rx));
                assert!(handle.app_recv.nonempty_hint.is_none());
                assert_eq!(handle.app_recv.capacity, capacity);
                assert_eq!(handle.app_send.capacity, tx_total / 2);
                assert!(
                    handle.app_send.map_cache.is_none(),
                    "TX threshold remains64KiB"
                );
                handle.app_recv
            })
            .collect();
        let payload = vec![0x5a; capacity + 1];
        let mut lifetimes = Vec::new();
        for queue in &queues {
            assert_eq!(queue.write(&payload), capacity);
            assert_eq!(queue.len(), capacity);
            lifetimes.push(queue.mapped_lifetime_for_test().unwrap());
            assert_eq!(queue.write(b"full"), 0);
        }
        let mut output = vec![0; capacity];
        for queue in &queues {
            assert_eq!(queue.read(&mut []), 0);
            assert_eq!(queue.len(), capacity);
            let retained_before = rx.retained_for_test();
            let half = capacity / 2;
            assert_eq!(queue.read(&mut output[..half]), half);
            assert_eq!(queue.len(), capacity - half);
            assert!(queue.mapped_lifetime_for_test().is_some());
            assert_eq!(rx.retained_for_test(), retained_before);
            assert_eq!(queue.read(&mut output[half..]), capacity - half);
            assert!(output.iter().all(|byte| *byte == 0x5a));
        }
        assert_eq!(rx.retained_for_test(), 2 * capacity);
        assert_eq!(tx.retained_for_test(), 0);
        assert!(lifetimes[0].upgrade().is_some());
        assert!(lifetimes[1].upgrade().is_some());
        assert!(
            lifetimes[2].upgrade().is_none(),
            "excess idle owner is actually destroyed"
        );
        let reused = TcpStreamHandle::new(capacity, tx_total / 2, Arc::new(Notify::new()))
            .with_rx_cache(Arc::downgrade(&rx))
            .app_recv;
        assert_eq!(reused.write(b"new"), 3);
        assert_eq!(reused.read(&mut output), 3);
        assert_eq!(&output[..3], b"new");
        assert_eq!(reused.read(&mut output), 0);
        rx.close();
        assert!(
            lifetimes
                .iter()
                .all(|lifetime| lifetime.upgrade().is_none())
        );
    }

    #[cfg(unix)]
    #[test]
    fn mapped_rx_failure_keeps_bounded_vec_progress_without_retries() {
        for (capacity, tx_total) in [(56 * 1024, 64 * 1024), (64 * 1024, 32 * 1024)] {
            assert_mapped_rx_failure(capacity, tx_total);
        }
    }

    #[cfg(unix)]
    fn assert_mapped_rx_failure(capacity: usize, tx_total: usize) {
        let cache = Arc::new(MapCache::new(2 * capacity));
        cache.fail_next_map.store(true, Ordering::Release);
        let queue = TcpStreamHandle::new(capacity, tx_total / 2, Arc::new(Notify::new()))
            .with_rx_cache(Arc::downgrade(&cache))
            .app_recv;
        let payload = vec![0x6b; capacity + 7];
        assert_eq!(queue.write(&payload), capacity);
        assert!(queue.lock().mapping_disabled);
        assert!(queue.mapped_lifetime_for_test().is_none());
        let mut output = vec![0; capacity];
        assert_eq!(queue.read(&mut output), capacity);
        assert_eq!(output, payload[..capacity]);
        for _ in 0..3 {
            assert_eq!(queue.write(b"vec"), 3);
            assert_eq!(queue.read(&mut output), 3);
            assert_eq!(&output[..3], b"vec");
        }
        assert_eq!(cache.map_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(cache.retained_for_test(), 0);
    }

    fn mapped_queue(capacity: usize, cache: &Arc<MapCache>) -> ByteQueue {
        TcpStreamHandle::new(16, capacity, Arc::new(Notify::new()))
            .with_tx_cache(Arc::downgrade(cache))
            .app_send
    }

    #[cfg(unix)]
    fn map_ring(capacity: usize) -> MappedByteRing {
        MappedByteRing::new(QueueMapping::new(capacity).unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_ring_wrap_partial_zero_and_full_keep_exact_order() {
        let mut ring = map_ring(8);
        assert_eq!(ring.write(b"abcdef"), 6);
        assert_eq!(ring.read(&mut []), 0);
        assert_eq!(ring.length, 6);
        let mut first = [0; 2];
        assert_eq!(ring.read(&mut first), 2);
        assert_eq!(&first, b"ab");
        assert_eq!(ring.write(b"WXYZextra"), 4);
        assert_eq!(ring.write(b"full"), 0);
        let mut output = [0; 8];
        assert_eq!(ring.read(&mut output), 6);
        assert_eq!(&output[..6], b"cdefWX");
        assert_eq!(ring.length, 2);
        assert_eq!(ring.read(&mut output[6..]), 2);
        assert_eq!(&output, b"cdefWXYZ");
        assert_eq!(ring.head, 0);
        assert!(ring.is_empty());
        assert_eq!(ring.read(&mut output), 0);
        assert_eq!(ring.write(&[]), 0);
        assert_eq!(ring.write(b"123456789"), 8);
        assert_eq!(ring.read(&mut output), 8);
        assert_eq!(&output, b"12345678");
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_only_large_send_uses_map_and_preserves_explicit_capacity() {
        let capacity = MAPPED_TX_MINIMUM + 3;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let large = mapped_queue(capacity, &cache);
        let body = vec![0x5a; capacity + 7];
        assert_eq!(large.write(&body), capacity);
        assert_eq!(large.lock().capacity(), capacity);
        assert!(large.mapped_lifetime_for_test().is_some());
        assert_eq!(large.write(b"full"), 0);
        let mut output = vec![0; capacity];
        assert_eq!(large.read(&mut output), capacity);
        assert!(output.iter().all(|byte| *byte == 0x5a));
        assert_eq!(cache.retained_for_test(), capacity);

        let small = mapped_queue(MAPPED_TX_MINIMUM - 1, &cache);
        let receive = ByteQueue::new(capacity);
        for queue in [&small, &receive] {
            assert_eq!(queue.write(b"vec"), 3);
            assert!(queue.mapped_lifetime_for_test().is_none());
            let retained = queue.lock().capacity();
            assert_eq!(queue.read(&mut [0; 3]), 3);
            assert_eq!(queue.lock().capacity(), retained);
        }
        assert_eq!(cache.retained_for_test(), capacity);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_tail_stays_owned_and_idle_reuse_exposes_only_new_bytes() {
        let capacity = MAPPED_TX_MINIMUM;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let first = mapped_queue(capacity, &cache);
        assert_eq!(first.write(b"first-flow-secret"), 17);
        let lifetime = first.mapped_lifetime_for_test().unwrap();
        let mut prefix = [0; 5];
        assert_eq!(first.read(&mut prefix), 5);
        assert_eq!(&prefix, b"first");
        assert_eq!(cache.retained_for_test(), 0);
        assert!(lifetime.upgrade().is_some());
        let mut tail = [0; 12];
        assert_eq!(first.read(&mut tail), 12);
        assert_eq!(&tail, b"-flow-secret");
        assert_eq!(cache.retained_for_test(), capacity);
        assert!(lifetime.upgrade().is_some());
        let attempts = cache.map_attempts.load(Ordering::Relaxed);
        let second = mapped_queue(capacity, &cache);
        assert_eq!(second.write(b"new"), 3);
        assert_eq!(cache.map_attempts.load(Ordering::Relaxed), attempts);
        assert_eq!(cache.retained_for_test(), 0);
        let mut output = [0x7f; 32];
        assert_eq!(second.read(&mut output), 3);
        assert_eq!(&output[..3], b"new");
        assert!(output[3..].iter().all(|byte| *byte == 0x7f));
        cache.close();
        assert!(lifetime.upgrade().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_cache_rejects_nonempty_full_slots_and_excess_bytes() {
        let cache = MapCache::new(8 * 4096);
        let mut nonempty = map_ring(4096);
        assert_eq!(nonempty.write(b"tail"), 4);
        let mut rejected = cache.put(nonempty).err().unwrap();
        let mut tail = [0; 4];
        assert_eq!(rejected.read(&mut tail), 4);
        assert_eq!(&tail, b"tail");
        for _ in 0..MAPPED_IDLE_SLOTS {
            assert!(cache.put(map_ring(4096)).is_ok());
        }
        assert_eq!(cache.retained_for_test(), MAPPED_IDLE_SLOTS * 4096);
        let extra = map_ring(4096);
        let lifetime = Arc::downgrade(&extra.mapping.lifetime);
        let retired = cache.put(extra).err().unwrap();
        assert!(lifetime.upgrade().is_some());
        drop(retired);
        assert!(lifetime.upgrade().is_none());
        let bounded = MapCache::new(4096);
        assert!(bounded.put(map_ring(4096)).is_ok());
        assert!(bounded.put(map_ring(4096)).is_err());
        assert_eq!(bounded.retained_for_test(), 4096);
        cache.close();
        bounded.close();
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_full_idle_budget_unmaps_a_returned_queue_backing() {
        let capacity = MAPPED_TX_MINIMUM;
        let cache = Arc::new(MapCache::new(capacity));
        let first = mapped_queue(capacity, &cache);
        let second = mapped_queue(capacity, &cache);
        assert_eq!(first.write(b"one"), 3);
        assert_eq!(second.write(b"two"), 3);
        let kept = first.mapped_lifetime_for_test().unwrap();
        let rejected = second.mapped_lifetime_for_test().unwrap();
        assert_eq!(first.read(&mut [0; 3]), 3);
        assert_eq!(cache.retained_for_test(), capacity);
        let mut output = [0; 3];
        assert_eq!(second.read(&mut output), 3);
        assert_eq!(&output, b"two");
        assert!(rejected.upgrade().is_none());
        assert!(kept.upgrade().is_some());
        assert_eq!(second.lock().capacity(), 0);
        cache.close();
        assert!(kept.upgrade().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_cache_contention_unmaps_return_without_rejecting_data() {
        let capacity = MAPPED_TX_MINIMUM;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let queue = mapped_queue(capacity, &cache);
        let guard = cache.state.lock().unwrap();
        assert_eq!(queue.write(b"progress"), 8);
        let lifetime = queue.mapped_lifetime_for_test().unwrap();
        let mut output = [0; 8];
        assert_eq!(queue.read(&mut output), 8);
        assert_eq!(&output, b"progress");
        assert!(lifetime.upgrade().is_none());
        drop(guard);
        assert_eq!(cache.retained_for_test(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_map_failure_keeps_bounded_vec_progress_without_retries() {
        let capacity = MAPPED_TX_MINIMUM + 3;
        let cache = Arc::new(MapCache::new(2 * capacity));
        cache.fail_next_map.store(true, Ordering::Release);
        let queue = mapped_queue(capacity, &cache);
        let payload = vec![0x5a; capacity + 5];
        assert_eq!(queue.write(&payload), capacity);
        assert!(queue.lock().mapping_disabled);
        assert!(queue.mapped_lifetime_for_test().is_none());
        assert_eq!(queue.write(b"full"), 0);
        assert!(queue.lock().capacity() <= capacity);
        let mut output = vec![0; capacity];
        assert_eq!(queue.read(&mut output), capacity);
        assert_eq!(output, payload[..capacity]);
        for _ in 0..4 {
            assert_eq!(queue.write(b"still-live"), 10);
            assert_eq!(queue.read(&mut output), 10);
            assert_eq!(&output[..10], b"still-live");
        }
        assert_eq!(cache.map_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(cache.retained_for_test(), 0);
        assert!(queue.lock().capacity() > 0);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_close_does_not_unmap_nonempty_tail_and_late_return_cannot_revive() {
        let capacity = MAPPED_TX_MINIMUM;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let queue = mapped_queue(capacity, &cache);
        assert_eq!(queue.write(b"retained-tail"), 13);
        let lifetime = queue.mapped_lifetime_for_test().unwrap();
        cache.close();
        assert!(lifetime.upgrade().is_some());
        let mut output = [0; 13];
        assert_eq!(queue.read(&mut output), 13);
        assert_eq!(&output, b"retained-tail");
        assert!(lifetime.upgrade().is_none());
        assert_eq!(cache.retained_for_test(), 0);
        assert_eq!(queue.write(b"late-vec"), 8);
        assert!(queue.mapped_lifetime_for_test().is_none());
        assert_eq!(queue.read(&mut output), 8);
        assert_eq!(&output[..8], b"late-vec");
        let expired = mapped_queue(capacity, &cache);
        drop(cache);
        assert!(queue.map_cache.as_ref().unwrap().upgrade().is_none());
        assert_eq!(expired.write(b"expired"), 7);
        assert!(expired.mapped_lifetime_for_test().is_none());
        assert!(expired.lock().mapping_disabled);
        assert_eq!(expired.read(&mut output), 7);
        assert_eq!(&output[..7], b"expired");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mapped_tx_stop_preserves_rx_tail_and_rejects_public_writes() {
        use tokio::io::AsyncReadExt;
        let capacity = MAPPED_TX_MINIMUM;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let handle = Arc::new(
            TcpStreamHandle::new(16, capacity, Arc::new(Notify::new()))
                .with_tx_cache(Arc::downgrade(&cache)),
        );
        let mut stream = TcpStream::new(
            FlowKey {
                source: "192.0.2.1:12000".parse().unwrap(),
                destination: "198.51.100.1:443".parse().unwrap(),
            },
            handle.clone(),
        );
        assert_eq!(handle.app_recv.write(b"accepted-tail"), 13);
        assert_eq!(handle.app_send.write(b"sent"), 4);
        let lifetime = handle.app_send.mapped_lifetime_for_test().unwrap();
        assert_eq!(handle.app_send.read(&mut [0; 4]), 4);
        assert!(cache.retained_for_test() > 0);
        cache.close();
        handle.mark_stopped();
        assert!(lifetime.upgrade().is_none());
        assert_eq!(
            stream.write_all(b"late").await.unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
        let mut tail = [0; 13];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"accepted-tail");
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(cache.retained_for_test(), 0);
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_large_tx_keeps_bounded_vec_progress_without_mapping() {
        let capacity = MAPPED_TX_MINIMUM + 3;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let queue = mapped_queue(capacity, &cache);
        assert!(queue.map_cache.is_none());
        let receive = TcpStreamHandle::new(56 * 1024, 16, Arc::new(Notify::new()))
            .with_rx_cache(Arc::downgrade(&cache))
            .app_recv;
        assert!(receive.map_cache.is_none());
        assert_eq!(receive.write(b"rx"), 2);
        assert!(receive.mapped_lifetime_for_test().is_none());
        assert_eq!(
            QueueMapping::new(capacity).err().unwrap().kind(),
            ErrorKind::Unsupported
        );
        let payload = vec![0x5a; capacity + 1];
        assert_eq!(queue.write(&payload), capacity);
        assert_eq!(queue.write(b"full"), 0);
        assert!(queue.mapped_lifetime_for_test().is_none());
        assert!(queue.lock().capacity() <= capacity);
        let mut output = vec![0; capacity];
        assert_eq!(queue.read(&mut output), capacity);
        assert!(output.iter().all(|byte| *byte == 0x5a));
        assert!(queue.lock().capacity() > 0);
        assert_eq!(queue.write(b"still-live"), 10);
        assert_eq!(queue.read(&mut output), 10);
        assert_eq!(&output[..10], b"still-live");
        assert_eq!(cache.map_attempts.load(Ordering::Relaxed), 0);
        assert_eq!(cache.retained_for_test(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tx_hint_preserves_partial_tail_reuse_and_vec_fallback() {
        let capacity = MAPPED_TX_MINIMUM;
        let cache = Arc::new(MapCache::new(2 * capacity));
        let queue = mapped_queue(capacity, &cache);
        assert!(!queue.may_have_data());
        assert_eq!(queue.write(b"abcdef"), 6);
        assert!(queue.may_have_data());
        assert_eq!(queue.read(&mut []), 0);
        assert!(queue.may_have_data());
        let mut prefix = [0; 2];
        assert_eq!(queue.read(&mut prefix), 2);
        assert_eq!(&prefix, b"ab");
        assert!(queue.may_have_data());
        assert_eq!(cache.retained_for_test(), 0);
        let mut tail = [0; 4];
        assert_eq!(queue.read(&mut tail), 4);
        assert_eq!(&tail, b"cdef");
        assert!(!queue.may_have_data());
        assert_eq!(cache.retained_for_test(), capacity);
        let attempts = cache.map_attempts.load(Ordering::Relaxed);
        assert_eq!(queue.write(b"xy"), 2);
        assert!(queue.may_have_data());
        assert_eq!(cache.map_attempts.load(Ordering::Relaxed), attempts);
        let lifetime = queue.mapped_lifetime_for_test().unwrap();
        cache.close();
        assert!(queue.may_have_data());
        assert_eq!(queue.read(&mut tail), 2);
        assert_eq!(&tail[..2], b"xy");
        assert!(!queue.may_have_data());
        assert!(lifetime.upgrade().is_none());
        assert_eq!(queue.write(b"v"), 1);
        assert!(queue.lock().mapping_disabled);
        assert!(queue.mapped_lifetime_for_test().is_none());
        assert!(queue.may_have_data());
        assert_eq!(queue.read(&mut tail), 1);
        assert_eq!(tail[0], b'v');
        assert!(!queue.may_have_data());
    }

    #[test]
    fn tx_hint_tracks_real_tail_after_zero_and_partial_operations() {
        let queue = ByteQueue::new_tx(8);
        assert!(!queue.may_have_data());
        assert_eq!(queue.write(b"abcdef"), 6);
        assert!(queue.may_have_data());
        assert_eq!(queue.read(&mut []), 0);
        assert!(queue.may_have_data());
        let mut prefix = [0; 2];
        assert_eq!(queue.read(&mut prefix), 2);
        assert_eq!(&prefix, b"ab");
        assert!(queue.may_have_data());
        assert_eq!(queue.write(b"WXYZextra"), 4);
        assert_eq!(queue.write(b"full"), 0);
        assert!(queue.may_have_data());
        let mut tail = [0; 8];
        let mut read = 0;
        while read < tail.len() {
            assert!(queue.may_have_data());
            assert_eq!(queue.len(), tail.len() - read);
            let count = queue.read(&mut tail[read..]);
            assert!(count > 0);
            read += count;
        }
        assert_eq!(&tail, b"cdefWXYZ");
        assert_eq!(queue.len(), 0);
        assert!(!queue.may_have_data());
        assert_eq!(queue.write(&[]), 0);
        assert_eq!(queue.read(&mut []), 0);
        assert!(!queue.may_have_data());
        assert_eq!(queue.write(b"next"), 4);
        assert!(queue.may_have_data());
        assert_eq!(queue.read(&mut tail), 4);
        assert_eq!(&tail[..4], b"next");
        assert!(!queue.may_have_data());
    }

    #[test]
    fn only_application_tx_queues_opt_in_to_the_advisory_hint() {
        let handle = TcpStreamHandle::new(7, 9, Arc::new(Notify::new()));
        assert!(handle.app_recv.nonempty_hint.is_none());
        assert!(handle.app_recv.may_have_data()); // Unknown, not a false empty.
        assert!(handle.app_send.nonempty_hint.is_some());
        assert!(!handle.app_send.may_have_data());
        assert_eq!(handle.app_recv.write(b"rx"), 2);
        assert!(handle.app_recv.may_have_data());
        assert_eq!(handle.app_send.write(b"123456789x"), 9);
        assert_eq!(handle.app_send.write(b"full"), 0);
        assert!(handle.app_send.may_have_data());
        let mut body = [0; 9];
        assert_eq!(handle.app_send.read(&mut body), 9);
        assert_eq!(&body, b"123456789");
        assert!(!handle.app_send.may_have_data());
    }

    #[test]
    fn byte_queue_never_exceeds_capacity() {
        let queue = ByteQueue::new(4);
        assert_eq!(queue.write(b"abcdef"), 4);
        assert_eq!(queue.len(), 4);
        assert_eq!(queue.write(b"g"), 0);
        let mut bytes = [0_u8; 8];
        assert_eq!(queue.read(&mut bytes), 4);
        assert_eq!(&bytes[..4], b"abcd");
    }

    #[test]
    fn byte_queue_grows_with_use_without_exceeding_its_storage_limit() {
        for limit in [16 * 1024, 16 * 1024 - 3] {
            let queue = ByteQueue::new(limit);
            assert_eq!(queue.lock().capacity(), 0);
            assert_eq!(queue.write(&[]), 0);
            assert_eq!(queue.lock().capacity(), 0);

            assert_eq!(queue.write(&[42]), 1);
            assert!(queue.lock().capacity() < limit);
            let mut hello = [0];
            assert_eq!(queue.read(&mut hello), 1);
            assert_eq!(hello, [42]);

            let payload: Vec<_> = (0_u8..=250).cycle().take(limit).collect();
            for chunk in payload.chunks(1460) {
                assert_eq!(queue.write(chunk), chunk.len());
                assert!(queue.lock().capacity() <= limit);
            }
            let full_capacity = queue.lock().capacity();
            assert_eq!(queue.len(), limit);
            assert_eq!(queue.write(b"full"), 0);
            assert_eq!(queue.lock().capacity(), full_capacity);

            let mut prefix = vec![0; 6 * 1024];
            assert_eq!(queue.read(&mut prefix), prefix.len());
            assert_eq!(prefix, payload[..prefix.len()]);
            let suffix = vec![7; prefix.len()];
            assert_eq!(queue.write(&suffix), suffix.len());
            let mut remaining = vec![0; limit];
            let mut received = 0;
            while received < limit {
                let count = queue.read(&mut remaining[received..]);
                assert!(count > 0);
                received += count;
            }
            assert_eq!(&remaining[..limit - suffix.len()], &payload[prefix.len()..]);
            assert_eq!(&remaining[limit - suffix.len()..], &suffix);
            assert!(queue.is_empty());
            assert_eq!(queue.lock().capacity(), full_capacity);
        }

        let queue = ByteQueue::new(13);
        assert_eq!(queue.write(b"abcdef"), 6);
        let mut prefix = [0; 4];
        assert_eq!(queue.read(&mut prefix), 4);
        assert_eq!(&prefix, b"abcd");
        assert_eq!(queue.write(b"ghijkl"), 6);
        assert!(queue.lock().capacity() <= 13);
        assert_eq!(queue.write(b"mnopq"), 5);
        assert_eq!(queue.write(b"full"), 0);
        assert!(queue.lock().capacity() <= 13);
        let mut remaining = [0; 13];
        let mut received = 0;
        while received < remaining.len() {
            let count = queue.read(&mut remaining[received..]);
            assert!(count > 0);
            received += count;
        }
        assert_eq!(&remaining, b"efghijklmnopq");
    }

    #[tokio::test]
    async fn closed_socket_unblocks_buffered_flush_and_rejects_writes() {
        let handle = Arc::new(TcpStreamHandle::new(16, 16, Arc::new(Notify::new())));
        let mut stream = TcpStream::new(
            FlowKey {
                source: "192.0.2.1:12000".parse().unwrap(),
                destination: "198.51.100.1:443".parse().unwrap(),
            },
            handle.clone(),
        );
        stream.write_all(b"buffered").await.unwrap();
        assert!(!handle.app_send.is_empty());

        handle.socket_closed.store(true, Ordering::Release);
        handle.write_closed.store(true, Ordering::Release);
        handle.send_waker.wake();

        let flush_error = tokio::time::timeout(Duration::from_millis(100), stream.flush())
            .await
            .expect("closed socket left flush pending")
            .expect_err("buffered flush on a closed socket must fail");
        assert_eq!(flush_error.kind(), ErrorKind::BrokenPipe);

        let write_error = stream
            .write_all(b"later")
            .await
            .expect_err("closed socket accepted another write");
        assert_eq!(write_error.kind(), ErrorKind::BrokenPipe);
    }
}
