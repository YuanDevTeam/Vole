//! Node-owned sing-mux sessions over supplied authenticated protocol streams.
//! No sockets, resolver, global pool, or detached protocol tasks live here.
use crate::{
    config::{SingMuxConfig, SingMuxProtocol},
    dispatch::BoxStream,
    resources::observation::{self, ResourceKind},
    session::Destination,
};
use bytes::Bytes;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::{Instant, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const IDLE_RETAINED: usize = crate::limits::SING_MUX_IDLE_CONNECTIONS;
mod brutal;
pub(crate) mod datagram;
mod h2_driver;
mod padding;
mod smux_driver;
mod yamux_driver;
pub(crate) struct Pool {
    options: SingMuxConfig,
    state: Arc<Mutex<State>>,
    opening: tokio::sync::Mutex<()>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    drained: Option<Arc<tokio::sync::Notify>>,
}
#[derive(Default)]
struct State {
    closed: bool,
    connections: Vec<Connection>,
}
struct Connection {
    sender: Sender,
    active: Arc<AtomicUsize>,
    issued: AtomicUsize,
    cancel: CancellationToken,
    _observation: observation::Guard,
}
#[derive(Clone)]
enum Sender {
    H2(super::h2_write::Sender),
    Yamux(yamux_driver::Client),
    Smux(smux_driver::Client),
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Pool {
    pub(crate) fn new(options: SingMuxConfig) -> Self {
        let drained = options.brutal.map(|_| Arc::new(tokio::sync::Notify::new()));
        Self {
            options,
            state: Arc::default(),
            opening: Default::default(),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            drained,
        }
    }
    pub(crate) fn only_tcp(&self) -> bool {
        self.options.only_tcp
    }
    pub(crate) async fn open<F, Fut>(
        &self,
        target: &Destination,
        udp: bool,
        deadline: Instant,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        let operation = async {
            let mut connect = Some(connect);
            let (sender, lease) = {
                let _opening = self.opening.lock().await;
                loop {
                    // notify_one stores a permit if the final lease drains
                    // between the state check and polling this waiter. The
                    // opening lock permits only one retirement waiter.
                    let notified = self.drained.as_ref().map(|notify| notify.notified());
                    let (existing, retiring) = {
                        let mut state = self.state.lock().unwrap();
                        if state.closed {
                            return Err(io::ErrorKind::ConnectionAborted.into());
                        }
                        state.connections.retain(|c| !c.cancel.is_cancelled());
                        let existing = state
                            .connections
                            .iter()
                            .filter(|c| c.can_admit())
                            .min_by_key(|c| c.active.load(Ordering::Acquire))
                            .filter(|c| {
                                let active = c.active.load(Ordering::Acquire);
                                self.options.brutal.is_some()
                                    || active == 0
                                    || if self.options.max_connections > 0 {
                                        state.connections.len() >= self.options.max_connections
                                            || active < self.options.min_streams
                                    } else {
                                        self.options.max_streams > 0
                                            && active < self.options.max_streams
                                    }
                            })
                            .map(|c| c.reserve(&self.state, self.drained.as_ref()));
                        let retiring = self.options.brutal.is_some()
                            && existing.is_none()
                            && !state.connections.is_empty();
                        (existing, retiring)
                    };
                    if let Some(pair) = existing {
                        break pair;
                    }
                    if retiring {
                        notified.expect("Brutal retirement notification").await;
                        continue;
                    }
                    let mut raw = connect.take().expect("one physical creation")().await?;
                    let protocol = match self.options.protocol {
                        SingMuxProtocol::Smux => 0,
                        SingMuxProtocol::Yamux => 1,
                        SingMuxProtocol::H2Mux => 2,
                    };
                    if self.options.padding {
                        let size = rand::random_range(256_usize..768);
                        let mut wire = vec![1, protocol, 1];
                        wire.extend_from_slice(&(size as u16).to_be_bytes());
                        wire.resize(5 + size, 0);
                        raw.write_all(&wire).await?;
                    } else {
                        raw.write_all(&[0, protocol]).await?;
                    }
                    raw.flush().await?;
                    if self.options.padding {
                        raw = Box::new(padding::Padding::new(raw));
                    }
                    let connection = self.establish(raw).await?;
                    if let Some(options) = self.options.brutal {
                        // This control stream consumes an actual transport ID
                        // even though it never becomes a business lease.
                        connection.issued.fetch_add(1, Ordering::AcqRel);
                        let mut control = connection.sender.open(deadline).await?;
                        brutal::exchange(&mut control, options.up, options.down).await?;
                    }
                    let mut state = self.state.lock().unwrap();
                    if state.closed {
                        return Err(io::ErrorKind::ConnectionAborted.into());
                    }
                    let pair = connection.reserve(&self.state, self.drained.as_ref());
                    state.connections.push(connection);
                    break pair;
                }
            };
            let mut raw = sender.open(deadline).await?;
            let mut request = Vec::with_capacity(262);
            request.extend_from_slice(&(if udp { 3_u16 } else { 0 }).to_be_bytes());
            crate::socks5::encode_address(target, &mut request)?;
            raw.write_all(&request).await?;
            raw.flush().await?;
            Ok(Box::new(ResponseStream {
                raw: Some(raw),
                lease: Some(lease),
                response: false,
                half_close: self.options.protocol != SingMuxProtocol::Smux,
                upload_closed: false,
                deadline: Box::pin(tokio::time::sleep_until(deadline)),
            }) as BoxStream)
        };
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
            result = timeout_at(deadline, operation) => result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
    async fn establish(&self, raw: BoxStream) -> io::Result<Connection> {
        if self.options.protocol == SingMuxProtocol::Smux {
            let (sender, driver) = smux_driver::new(raw);
            return self.own(Sender::Smux(sender), driver);
        }
        if self.options.protocol == SingMuxProtocol::Yamux {
            let (sender, driver) = yamux_driver::new(raw);
            return self.own(Sender::Yamux(sender), driver);
        }
        let (sender, driver) = h2_driver::new(raw).await?;
        self.own(Sender::H2(sender), driver)
    }
    fn own(
        &self,
        sender: Sender,
        driver: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<Connection> {
        let cancel = self.cancel.child_token();
        let token = cancel.clone();
        let drained = self.drained.clone();
        let state = self.state.lock().unwrap();
        if state.closed {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let guard = observation::track(ResourceKind::Task);
        self.tasks.spawn(observation::bind(async move {
            let _guard = guard;
            tokio::select! { biased; ()=token.cancelled()=>{}, _=driver=>{} }
            token.cancel();
            if let Some(drained) = drained {
                drained.notify_one();
            }
        }));
        Ok(Connection {
            sender,
            active: Arc::default(),
            issued: AtomicUsize::new(0),
            cancel,
            _observation: observation::track(ResourceKind::Pool),
        })
    }
    pub(crate) fn begin_stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.cancel.cancel();
        state.connections.clear();
        self.tasks.close();
    }
    pub(crate) async fn stop(&self) {
        self.begin_stop();
        self.tasks.wait().await;
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.begin_stop();
    }
}
impl Sender {
    async fn open(&self, deadline: Instant) -> io::Result<BoxStream> {
        match self {
            Self::H2(sender) => super::grpc::mux_stream(sender.clone(), deadline).await,
            Self::Yamux(sender) => sender.open().await,
            Self::Smux(sender) => sender.open().await,
        }
    }
}
impl Connection {
    fn can_admit(&self) -> bool {
        !matches!(self.sender, Sender::Yamux(_))
            || self.issued.load(Ordering::Acquire) < yamux_driver::STREAMS
    }
    fn reserve(
        &self,
        pool: &Arc<Mutex<State>>,
        drained: Option<&Arc<tokio::sync::Notify>>,
    ) -> (Sender, Lease) {
        self.active.fetch_add(1, Ordering::AcqRel);
        // A dropped logical lease is not proof that yamux has processed its
        // reset. Its public poll_new_outbound closes the entire connection on
        // TooManyStreams, including siblings. Retire admission after a bounded
        // number of issued streams; let existing ones drain on the old driver.
        // This is a per-transport retirement budget, never a node-wide quota.
        self.issued.fetch_add(1, Ordering::AcqRel);
        (
            self.sender.clone(),
            Lease {
                active: self.active.clone(),
                pool: Arc::downgrade(pool),
                drained: drained.cloned(),
            },
        )
    }
}
struct Lease {
    active: Arc<AtomicUsize>,
    pool: Weak<Mutex<State>>,
    drained: Option<Arc<tokio::sync::Notify>>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        if let Some(pool) = self.pool.upgrade() {
            let mut idle = 0;
            pool.lock().unwrap().connections.retain(|c| {
                if c.cancel.is_cancelled() {
                    return false;
                }
                if c.active.load(Ordering::Acquire) > 0 {
                    return true;
                }
                if matches!(c.sender, Sender::Yamux(_))
                    && c.issued.load(Ordering::Acquire) >= yamux_driver::STREAMS
                {
                    return false;
                }
                idle += 1;
                idle <= IDLE_RETAINED
            });
        }
        if let Some(drained) = &self.drained {
            drained.notify_one();
        }
    }
}
struct ResponseStream {
    raw: Option<BoxStream>,
    lease: Option<Lease>,
    response: bool,
    half_close: bool,
    upload_closed: bool,
    deadline: Pin<Box<tokio::time::Sleep>>,
}
impl AsyncRead for ResponseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 || self.raw.is_none() {
            return Poll::Ready(Ok(()));
        }
        if !self.response {
            // A pooled physical connection does not extend this logical
            // stream's setup deadline, including an already-buffered status.
            if self.deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
            let mut status = [0];
            let mut buf = ReadBuf::new(&mut status);
            ready!(Pin::new(self.raw.as_mut().unwrap()).poll_read(cx, &mut buf))?;
            if buf.filled() != [0] {
                self.raw.take();
                self.lease.take();
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "sing-mux stream rejected",
                )));
            }
            self.response = true;
        }
        Pin::new(self.raw.as_mut().unwrap()).poll_read(cx, out)
    }
}
impl AsyncWrite for ResponseStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.upload_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(self.raw.as_mut().ok_or(io::ErrorKind::BrokenPipe)?).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.raw.as_mut().ok_or(io::ErrorKind::BrokenPipe)?).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.upload_closed {
            return Poll::Ready(Ok(()));
        }
        if let Some(raw) = &mut self.raw {
            ready!(Pin::new(raw).poll_shutdown(cx))?;
        }
        self.upload_closed = true;
        if !self.half_close {
            self.raw.take();
            self.lease.take();
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn half_close_keeps_the_read_side_and_lease_until_drop() {
        for half_close in [false, true] {
            let (raw, mut peer) = tokio::io::duplex(16);
            let active = Arc::new(AtomicUsize::new(1));
            let mut stream = ResponseStream {
                raw: Some(Box::new(raw)),
                lease: Some(Lease {
                    active: active.clone(),
                    pool: Weak::new(),
                    drained: None,
                }),
                response: true,
                half_close,
                upload_closed: false,
                deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(1))),
            };
            stream.write_all(b"upload").await.unwrap();
            stream.shutdown().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut uploaded = Vec::new();
            peer.read_to_end(&mut uploaded).await.unwrap();
            assert_eq!(uploaded, b"upload");
            assert_eq!(active.load(Ordering::Acquire), usize::from(half_close));
            if half_close {
                peer.write_all(b"tail").await.unwrap();
                peer.shutdown().await.unwrap();
                let mut tail = Vec::new();
                stream.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, b"tail");
                assert_eq!(active.load(Ordering::Acquire), 1);
            } else {
                assert_eq!(stream.read(&mut [0; 4]).await.unwrap(), 0);
            }
            drop(stream);
            assert_eq!(active.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_status_obeys_setup_deadline_but_established_reads_do_not() {
        for timing in ["late-first-poll", "late-after-pending", "established"] {
            let (raw, mut peer) = tokio::io::duplex(16);
            let mut stream = ResponseStream {
                raw: Some(Box::new(raw)),
                lease: None,
                response: false,
                half_close: true,
                upload_closed: false,
                deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(1))),
            };
            if timing == "late-after-pending" {
                assert!(futures_util::poll!(std::pin::pin!(stream.read_u8())).is_pending());
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
            }
            peer.write_all(b"\x00a").await.unwrap();
            if timing == "established" {
                assert_eq!(stream.read_u8().await.unwrap(), b'a');
            }
            if timing != "late-after-pending" {
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
            }
            assert_eq!(stream.read(&mut []).await.unwrap(), 0);
            peer.write_all(b"b").await.unwrap();
            if timing == "established" {
                assert_eq!(stream.read_u8().await.unwrap(), b'b');
            } else {
                assert_eq!(
                    stream.read_u8().await.unwrap_err().kind(),
                    io::ErrorKind::TimedOut,
                    "{timing}"
                );
                // A late response cannot revive a stream after a timeout.
                assert_eq!(
                    stream.read_u8().await.unwrap_err().kind(),
                    io::ErrorKind::TimedOut
                );
            }
        }
    }
}
