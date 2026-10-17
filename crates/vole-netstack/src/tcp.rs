use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Read as _},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use futures_util::task::AtomicWaker;
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

/// A bounded queue whose allocation is made once when a flow is accepted.
pub(crate) struct ByteQueue {
    bytes: Mutex<VecDeque<u8>>,
    capacity: usize,
}

impl ByteQueue {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<u8>> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn write(&self, source: &[u8]) -> usize {
        let mut bytes = self.lock();
        let count = source.len().min(self.capacity - bytes.len());
        bytes.extend(&source[..count]);
        count
    }

    pub(crate) fn read(&self, destination: &mut [u8]) -> usize {
        self.lock()
            .read(destination)
            .expect("reading an in-memory queue cannot fail")
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
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
    pub(crate) fn new(
        app_recv_buffer: usize,
        app_send_buffer: usize,
        driver_notify: Arc<Notify>,
    ) -> Self {
        Self {
            app_recv: ByteQueue::new(app_recv_buffer),
            app_send: ByteQueue::new(app_send_buffer),
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
}

impl TcpStream {
    pub(crate) fn new(flow: FlowKey, handle: Arc<TcpStreamHandle>) -> Self {
        Self { flow, handle }
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
        let target = buffer.initialize_unfilled();
        let count = self.handle.app_recv.read(target);
        if count > 0 {
            buffer.advance(count);
            self.notify_driver();
            return Poll::Ready(Ok(()));
        }

        if self.handle.read_closed.load(Ordering::Acquire)
            || self.handle.socket_closed.load(Ordering::Acquire)
            || self.handle.stopped.load(Ordering::Acquire)
        {
            return Poll::Ready(Ok(()));
        }

        self.handle.recv_waker.register(context.waker());
        let count = self.handle.app_recv.read(buffer.initialize_unfilled());
        if count > 0 {
            buffer.advance(count);
            self.notify_driver();
            Poll::Ready(Ok(()))
        } else if self.handle.read_closed.load(Ordering::Acquire)
            || self.handle.socket_closed.load(Ordering::Acquire)
            || self.handle.stopped.load(Ordering::Acquire)
        {
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
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;

    use super::*;

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
