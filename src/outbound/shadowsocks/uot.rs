//! SS-specific ownership around the shared v2 datagram module. A reader cannot
//! initialize SS, and ending that reader releases IO even if a caller keeps the
//! association after Stop. AnyTLS retains its separate stream/FIN ownership.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker, ready},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::ShadowsocksOutbound;
use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::{
        DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest, EstablishContext, OutboundConnector,
        uot::{UotTransport, magic_destination},
    },
    session::{Datagram, Destination, StreamSession},
};

#[derive(Default)]
pub(super) struct Owner {
    closed: Mutex<bool>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
}

impl Owner {
    pub(super) async fn open(
        &self,
        outbound: &ShadowsocksOutbound,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let stream = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(DispatchError::NotAllowed),
            result = outbound.connect_stream(StreamSession {
                metadata: request.session.metadata.clone(),
                inbound: request.session.inbound,
                source: request.session.source,
                destination: magic_destination(),
                sniffed_domain: None,
            }, context) => result?.io,
        };
        // Admission and task registration share Stop's lock. A completed TCP
        // handshake racing Stop cannot introduce a new untracked read task.
        let closed = self
            .closed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *closed {
            return Err(DispatchError::NotAllowed);
        }
        let io = Arc::new(Mutex::new(FirstWrite {
            io: Some(stream),
            deadline: Some(Box::pin(tokio::time::sleep_until(context.deadline()))),
            written: false,
            readable: false,
            failure: io::ErrorKind::BrokenPipe,
            reader: None,
            writer: None,
        }));
        let transport = UotTransport::new(
            Reader(io.clone()),
            Writer(io),
            request.max_response_payload_size(),
            self.cancellation.clone(),
            &self.tasks,
        );
        Ok(crate::dispatch::bound_datagram(
            Box::new(DatagramAdapter {
                inner: transport,
                resolution: context.resolution(),
                first_deadline: Some(context.deadline()),
                cancellation: self.cancellation.clone(),
            }),
            request.budget(),
        ))
    }

    pub(super) fn begin_shutdown(&self) {
        *self
            .closed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.cancellation.cancel();
        self.tasks.close();
    }

    pub(super) async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.close();
    }
}

struct DatagramAdapter {
    inner: UotTransport,
    resolution: ResolutionContext,
    first_deadline: Option<Instant>,
    cancellation: CancellationToken,
}

#[async_trait]
impl DatagramTransport for DatagramAdapter {
    async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
        let deadline = self
            .first_deadline
            .unwrap_or_else(|| Instant::now() + DEFAULT_ESTABLISH_TIMEOUT);
        datagram.remote = Destination::Ip(tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(DispatchError::NotAllowed),
            result = self.resolution.resolve_ip(&datagram.remote, deadline) => result?,
        });
        self.inner.send(datagram).await?;
        self.first_deadline = None;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.inner.receive().await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.inner.close().await
    }
}

struct FirstWrite {
    io: Option<BoxStream>,
    deadline: Option<Pin<Box<Sleep>>>,
    written: bool,
    readable: bool,
    failure: io::ErrorKind,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl FirstWrite {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self
            .deadline
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            self.fail(io::ErrorKind::TimedOut);
        }
        if self.io.is_none() {
            return Err(io::Error::new(
                self.failure,
                "Shadowsocks UoT stream is closed",
            ));
        }
        Ok(())
    }

    fn fail(&mut self, kind: io::ErrorKind) {
        if self.io.take().is_some() {
            self.failure = kind;
        }
        self.deadline = None;
        for waker in [self.reader.take(), self.writer.take()]
            .into_iter()
            .flatten()
        {
            waker.wake();
        }
    }
}

struct Reader(Arc<Mutex<FirstWrite>>);
struct Writer(Arc<Mutex<FirstWrite>>);

impl Drop for Reader {
    fn drop(&mut self) {
        // Task completion (including cancellation/abort) releases the actual
        // stream, not just one Tokio split handle. No shutdown/empty SS write.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail(io::ErrorKind::ConnectionAborted);
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.check(cx)?;
        if !state.readable {
            state.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(state.io.as_mut().unwrap()).poll_read(cx, out)
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.check(cx)?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        state.writer = Some(cx.waker().clone());
        state.written = true;
        Pin::new(state.io.as_mut().unwrap()).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.check(cx)?;
        state.writer = Some(cx.waker().clone());
        if !state.written {
            return Poll::Ready(Ok(()));
        }
        ready!(Pin::new(state.io.as_mut().unwrap()).poll_flush(cx))?;
        state.readable = true;
        state.deadline = None;
        if let Some(waker) = state.reader.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail(io::ErrorKind::BrokenPipe);
        Poll::Ready(Ok(()))
    }
}
