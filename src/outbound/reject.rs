//! Functional rejection without opening a physical connection.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    dispatch::{DatagramTransport, DispatchError},
    session::{Datagram, StreamSession},
};

use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};

const DROP_DELAY: Duration = Duration::from_secs(60);

/// A named reject ends immediately. The reserved REJECT-DROP delays TCP only;
/// neither mode creates sockets, queues or detached work.
#[derive(Debug, Default)]
pub(crate) struct RejectOutbound {
    drop: bool,
    cancel: CancellationToken,
}

impl RejectOutbound {
    pub(crate) fn drop_connections() -> Self {
        Self::with_drop_cancellation(CancellationToken::new())
    }

    pub(crate) fn with_drop_cancellation(cancel: CancellationToken) -> Self {
        Self { drop: true, cancel }
    }
}

#[async_trait]
impl OutboundConnector for RejectOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        if context.deadline() <= Instant::now() {
            return Err(DispatchError::TimedOut);
        }
        Ok(ConnectedStream {
            io: Box::new(RejectedStream::new(self.drop, self.cancel.clone())),
            effective_peer: session.destination,
        })
    }

    async fn open_datagram(
        &self,
        _request: DatagramRequest,
        _context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        Ok(Box::new(RejectedDatagram))
    }

    fn begin_shutdown(&self) {
        self.cancel.cancel();
    }
}

type Wait = Pin<Box<dyn Future<Output = ()> + Send>>;

struct RejectedStream {
    read_wait: Option<Wait>,
    write_wait: Option<Wait>,
}

impl RejectedStream {
    fn new(drop: bool, cancel: CancellationToken) -> Self {
        let deadline = Instant::now() + DROP_DELAY;
        let wait = |cancel: CancellationToken| -> Wait {
            Box::pin(async move {
                tokio::select! { biased;
                    () = cancel.cancelled() => {},
                    () = tokio::time::sleep_until(deadline) => {},
                }
            })
        };
        Self {
            read_wait: drop.then(|| wait(cancel.clone())),
            write_wait: drop.then(|| wait(cancel)),
        }
    }

    fn ready(wait: &mut Option<Wait>, context: &mut Context<'_>) -> Poll<()> {
        if let Some(wait) = wait {
            std::task::ready!(wait.as_mut().poll(context));
        }
        Poll::Ready(())
    }
}

impl AsyncRead for RejectedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() > 0 {
            std::task::ready!(Self::ready(&mut self.read_wait, context));
            self.read_wait = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RejectedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Tokio's bidirectional relay exits on a write error. Retain the
        // bounded caller buffer until DROP expires instead of ending early.
        std::task::ready!(Self::ready(&mut self.write_wait, context));
        self.write_wait = None;
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct RejectedDatagram;

#[async_trait]
impl DatagramTransport for RejectedDatagram {
    fn supports_shared_destinations(&self) -> bool {
        true
    }

    async fn send(&mut self, _packet: Datagram) -> Result<(), DispatchError> {
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
    }

    fn supports_poll_receive(&self) -> bool {
        true
    }

    fn poll_receive(
        &mut self,
        _context: &mut Context<'_>,
        _scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()))
    }
}

#[cfg(test)]
#[path = "reject_tests.rs"]
mod tests;
