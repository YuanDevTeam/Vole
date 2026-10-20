//! Linux TFO adapter over the already protected and bound physical socket.
//!
//! The duplicate is the SAME protected/bound socket, not a second connection.
//! It exists only until the initial connection completes or is cancelled.
use std::{
    future::Future,
    io,
    net::Shutdown,
    os::fd::AsRawFd,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use futures_util::task::AtomicWaker;
use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::TcpStream,
    sync::Notify,
    time::{Instant, timeout_at},
};
use tokio_tfo::TfoStream;
use tokio_util::sync::CancellationToken;

use super::{SocketInitialization, socket_initialization_cancelled};
use crate::resources::observation::{ResourceKind, track};

#[derive(Debug)]
struct Handshake {
    deadline: Instant,
    result: OnceLock<io::Result<()>>,
    activated: Notify,
    read: AtomicWaker,
    write: AtomicWaker,
    cancellation: CancellationToken,
}

impl Handshake {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            result: OnceLock::new(),
            activated: Notify::new(),
            read: AtomicWaker::new(),
            write: AtomicWaker::new(),
            cancellation: CancellationToken::new(),
        }
    }

    fn complete(&self, result: io::Result<()>) {
        if self.result.set(result).is_ok() {
            self.read.wake();
            self.write.wake();
        }
    }

    fn status(&self) -> Option<io::Result<()>> {
        if self.result.get().is_none() && Instant::now() >= self.deadline {
            self.complete(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connect timed out",
            )));
            self.cancellation.cancel();
        }
        self.result.get().map(|result| match result {
            Ok(()) => Ok(()),
            Err(error) => Err(error.raw_os_error().map_or_else(
                || io::Error::new(error.kind(), "TCP Fast Open establishment failed"),
                io::Error::from_raw_os_error,
            )),
        })
    }

    fn poll(&self, cx: &mut Context<'_>, write: bool) -> Poll<io::Result<()>> {
        if write {
            self.write.register(cx.waker());
        } else {
            self.read.register(cx.waker());
        }
        self.status().map_or(Poll::Pending, Poll::Ready)
    }
}

/// Explicitly pending until the shared physical handshake owner confirms it.
/// This must not be used as an eager Happy-Eyeballs winner.
pub(crate) struct PendingFastOpen {
    inner: TfoStream,
    handshake: Arc<Handshake>,
    activated: bool,
}

impl std::fmt::Debug for PendingFastOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingFastOpen").finish_non_exhaustive()
    }
}

impl PendingFastOpen {
    pub(super) fn new(
        inner: TfoStream,
        deadline: Instant,
        owner: &Arc<SocketInitialization>,
    ) -> io::Result<Self> {
        if owner.cancellation.is_cancelled() {
            return Err(socket_initialization_cancelled());
        }
        let handshake = Arc::new(Handshake::new(deadline));
        // A cold-cookie connect may already have completed before TfoStream is
        // returned. Do not keep its setup timer attached to established I/O.
        if connected(&inner)? {
            handshake.complete(Ok(()));
        } else {
            let duplicate = SockRef::from(&inner).try_clone()?;
            duplicate.set_nonblocking(true)?;
            let control = TcpStream::from_std(duplicate.into())?;
            let socket_guard = track(ResourceKind::Socket);
            let state = Arc::clone(&handshake);
            let cancellation = owner.cancellation.clone();
            spawn_owned(owner, async move {
                let _socket_guard = socket_guard;
                let operation = async {
                    state.activated.notified().await;
                    // A real zero-byte send, rather than a synthetic
                    // WouldBlock based on TCP_INFO, owns readiness clearing.
                    // Its cold/warm/pending behavior is a real-kernel PoC gate.
                    control
                        .async_io(Interest::WRITABLE, || {
                            SockRef::from(&control).send(&[]).map(|_| ())
                        })
                        .await?;
                    if !connected(&control)? {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TFO readiness confirmation did not establish TCP",
                        ));
                    }
                    Ok(())
                };
                let result = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => Err(socket_initialization_cancelled()),
                    () = state.cancellation.cancelled() => Err(socket_initialization_cancelled()),
                    result = timeout_at(deadline, operation) => result.unwrap_or_else(|_| {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))
                    }),
                };
                if result.is_err() {
                    let _ = SockRef::from(&control).shutdown(Shutdown::Both);
                }
                // The duplicate is released before publishing completion and
                // before the owning task's tracking token can be released.
                drop(control);
                state.complete(result);
            })?;
        }
        Ok(Self {
            inner,
            handshake,
            activated: false,
        })
    }

    fn check(&self) -> io::Result<()> {
        self.handshake.status().unwrap_or(Ok(()))
    }

    fn reject(&self, error: &io::Error) {
        if self.handshake.result.get().is_none() {
            self.handshake
                .complete(Err(error.raw_os_error().map_or_else(
                    || io::Error::new(error.kind(), "TCP Fast Open establishment failed"),
                    io::Error::from_raw_os_error,
                )));
            self.handshake.cancellation.cancel();
        }
    }

    fn activate(&mut self) {
        if !self.activated {
            self.activated = true;
            self.handshake.activated.notify_one();
        }
    }

    fn poll_activate(&mut self, cx: &mut Context<'_>, write: bool) -> Poll<io::Result<()>> {
        self.check()?;
        if !self.activated && self.handshake.result.get().is_none() {
            match Pin::new(&mut self.inner).poll_write(cx, &[]) {
                Poll::Ready(Ok(0)) => self.activate(),
                Poll::Ready(Ok(_)) => unreachable!("empty write cannot accept bytes"),
                Poll::Ready(Err(error)) => {
                    self.reject(&error);
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.handshake.poll(cx, write)
    }
}

impl AsyncRead for PendingFastOpen {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.poll_activate(cx, false))?;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PendingFastOpen {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return self.poll_activate(cx, true).map_ok(|()| 0);
        }
        self.check()?;
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.reject(error);
        }
        if matches!(result, Poll::Ready(Ok(_))) {
            // Report the library's accepted count immediately, without storing
            // or retrying payload. Only then may the control owner send empty.
            self.activate();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_activate(cx, true))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_activate(cx, true))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for PendingFastOpen {
    fn drop(&mut self) {
        self.handshake.cancellation.cancel();
    }
}

fn spawn_owned(
    owner: &SocketInitialization,
    future: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let token = {
        let closed = owner
            .closed
            .lock()
            .map_err(|_| io::Error::other("socket initialization lock is poisoned"))?;
        if *closed {
            return Err(socket_initialization_cancelled());
        }
        owner.tasks.token()
    };
    let guard = track(ResourceKind::Task);
    tokio::spawn(async move {
        let _token = token;
        let _guard = guard;
        future.await;
    });
    Ok(())
}

fn connected(stream: &impl AsRawFd) -> io::Result<bool> {
    let mut value = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
    let mut length = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    // SAFETY: the owned stream stays live, and the output and length match
    // Linux's public TCP_INFO ABI. No borrowed descriptor escapes the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            value.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty TCP_INFO"));
    }
    // SAFETY: zero-initialized output remains fully initialized for a short
    // response; the kernel has provided at least the first state byte.
    let state = unsafe { value.assume_init() }.tcpi_state;
    Ok(matches!(state, 1 | 8)) // Linux TCP_ESTABLISHED / TCP_CLOSE_WAIT.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pending_setup_expires_but_confirmed_connection_keeps_its_io_lifetime() {
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let pending = Handshake::new(deadline);
        let connected = Handshake::new(deadline);
        connected.complete(Ok(()));
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        assert_eq!(
            pending.status().unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(pending.cancellation.is_cancelled());
        assert!(connected.status().unwrap().is_ok());
        assert!(!connected.cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn pending_handshake_registration_is_owned_after_submission_returns_and_stop_joins() {
        let owner = Arc::new(SocketInitialization::default());
        let cancellation = owner.cancellation.clone();
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = exited.clone();
        spawn_owned(&owner, async move {
            cancellation.cancelled().await;
            tokio::task::yield_now().await;
            observed.store(true, std::sync::atomic::Ordering::Release);
        })
        .unwrap();
        assert_eq!(owner.tasks.len(), 1);
        owner.shutdown().await;
        assert!(exited.load(std::sync::atomic::Ordering::Acquire));
        assert!(owner.tasks.is_empty());
        assert!(spawn_owned(&owner, async {}).is_err());
    }
}

#[cfg(all(test, feature = "tun"))]
#[path = "dialer_fast_open_gate.rs"]
mod gate;
