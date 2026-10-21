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
pub(crate) struct SuppliedStream {
    pub io: BoxStream,
    #[cfg(target_os = "linux")]
    pub control: Option<crate::dialer::tcp_control::Control>,
}
pub(crate) struct Pool {
    options: SingMuxConfig,
    autonomous_writes: bool,
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
            autonomous_writes: false,
            state: Arc::default(),
            opening: Default::default(),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            drained,
        }
    }
    pub(crate) fn set_autonomous_writes(&mut self, enabled: bool) {
        self.autonomous_writes =
            enabled && self.options.protocol == SingMuxProtocol::Smux && !self.options.padding;
    }
    pub(crate) fn autonomous_writes(&self) -> bool {
        self.autonomous_writes
    }
    pub(crate) fn only_tcp(&self) -> bool {
        self.options.only_tcp
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn brutal_enabled(&self) -> bool {
        self.options.brutal.is_some()
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
        Fut: Future<Output = io::Result<SuppliedStream>>,
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
                    let supplied = connect.take().expect("one physical creation")().await?;
                    let mut raw = supplied.io;
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
                        let rate = brutal::exchange(&mut control, options.up, options.down).await?;
                        #[cfg(target_os = "linux")]
                        if let Some(physical) = supplied.control
                            && let Err(error) = physical.apply_brutal(rate)
                        {
                            tracing::debug!(error_kind = ?error.kind(), "local TCP Brutal unavailable");
                        }
                        #[cfg(not(target_os = "linux"))]
                        let _ = rate;
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
                deadline: Some(Box::pin(tokio::time::sleep_until(deadline))),
            }) as BoxStream)
        };
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
            result = timeout_at(deadline, operation) => result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
    async fn establish(&self, raw: BoxStream) -> io::Result<Connection> {
        if self.options.protocol == SingMuxProtocol::Smux {
            let (sender, driver) =
                smux_driver::new_with_autonomous_writes(raw, self.autonomous_writes);
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
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl ResponseStream {
    fn check_setup(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
        {
            self.raw.take();
            self.lease.take();
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
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
        self.check_setup(cx)?;
        if !self.response {
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
            self.deadline = None;
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
        self.check_setup(cx)?;
        let result =
            Pin::new(self.raw.as_mut().ok_or(io::ErrorKind::BrokenPipe)?).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            // A peer may delay both HTTP headers and mux status until target
            // data exists. Only actual business writes reach this wrapper;
            // Pool::open has already flushed the mux request metadata.
            self.deadline = None;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_setup(cx)?;
        Pin::new(self.raw.as_mut().ok_or(io::ErrorKind::BrokenPipe)?).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.upload_closed {
            return Poll::Ready(Ok(()));
        }
        self.check_setup(cx)?;
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
                deadline: None,
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
                deadline: Some(Box::pin(tokio::time::sleep(
                    std::time::Duration::from_secs(1),
                ))),
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
                // Timeout closes the supplied IO and lease; late writes or
                // already-buffered status cannot revive this logical stream.
                assert!(stream.raw.is_none());
                assert!(stream.lease.is_none());
                assert!(stream.write(b"late").await.is_err());
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            }
        }
    }
    fn pending_status(raw: BoxStream, deadline: Instant) -> ResponseStream {
        ResponseStream {
            raw: Some(raw),
            lease: None,
            response: false,
            half_close: true,
            upload_closed: false,
            deadline: Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn h2mux_unread_siblings_do_not_block_a_short_response() {
        use crate::transport::h2_write::{Payload, Writes};
        use std::time::Duration;

        let (raw, peer) = tokio::io::duplex(65536);
        let (peer, writes) = Writes::wrap(Box::new(peer));
        let (accepted, mut requests) = tokio::sync::mpsc::channel(1);
        let peer_driver = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .handshake::<_, Payload>(peer)
                .await
                .unwrap();
            while let Some(Ok(request)) = connection.accept().await {
                if accepted.send(request).await.is_err() {
                    break;
                }
            }
        });
        let (sender, driver) = h2_driver::new(Box::new(raw)).await.unwrap();
        let client_driver = tokio::spawn(driver);
        let sender = Sender::H2(sender);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut streams = Vec::new();
        let mut peer_streams = Vec::new();
        let mut short_receipt = None;

        for index in 0..3 {
            let mut raw = sender.open(deadline).await.unwrap();
            let metadata = [0, if index == 2 { 3 } else { 0 }, 1, 192, 0, 2, 1, 1, 187];
            raw.write_all(&metadata).await.unwrap();
            raw.flush().await.unwrap();
            let (request, mut response) = requests.recv().await.unwrap();
            let mut input = request.into_body();
            let first = input.data().await.unwrap().unwrap();
            assert_eq!(first.as_ref(), metadata);
            input.flow_control().release_capacity(first.len()).unwrap();
            let mut output = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            let body = if index == 2 {
                Bytes::from_static(&[0, 42])
            } else {
                let mut body = vec![b'a' + index; 65536];
                body[0] = 0;
                Bytes::from(body)
            };
            let (payload, receipt) = writes.payload(body);
            output.send_data(payload, false).unwrap();
            if index < 2 {
                // The held streams consume actual connection credit before
                // opening the short stream; enqueueing DATA alone is no proof.
                tokio::time::timeout(Duration::from_secs(1), receipt)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            } else {
                short_receipt = Some(receipt);
            }
            streams.push(pending_status(raw, deadline));
            peer_streams.push((input, output));
        }

        let mut short = streams.pop().unwrap();
        let short_response =
            tokio::time::timeout(Duration::from_millis(100), short.read_u8()).await;
        // Neither held sibling has been read or dropped at this point. The
        // short stream must make progress without borrowing their credit.
        for (index, stream) in streams.iter_mut().enumerate() {
            let mut payload = vec![0; 65535];
            tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut payload))
                .await
                .unwrap()
                .unwrap();
            assert!(payload.iter().all(|byte| *byte == b'a' + index as u8));
        }
        tokio::time::timeout(Duration::from_secs(1), short_receipt.unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(short);
        drop(streams);
        drop(peer_streams);
        client_driver.abort();
        let _ = client_driver.await;
        peer_driver.abort();
        let _ = peer_driver.await;
        assert!(
            matches!(short_response, Ok(Ok(42))),
            "unread siblings blocked the short response: {short_response:?}"
        );
    }

    enum NoBusinessWrite {
        Pending,
        Zero,
        Error,
    }
    impl AsyncRead for NoBusinessWrite {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for NoBusinessWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                Self::Pending => Poll::Pending,
                Self::Zero => Poll::Ready(Ok(0)),
                Self::Error => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn empty_pending_and_error_writes_do_not_release_setup_deadline() {
        for raw in [
            NoBusinessWrite::Pending,
            NoBusinessWrite::Zero,
            NoBusinessWrite::Error,
        ] {
            let mut stream = pending_status(
                Box::new(raw),
                Instant::now() + std::time::Duration::from_secs(1),
            );
            let _ = futures_util::poll!(std::pin::pin!(stream.write(b"payload")));
            assert!(stream.deadline.is_some());
            tokio::time::advance(std::time::Duration::from_secs(2)).await;
            assert_eq!(
                stream.write(b"late").await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert!(stream.raw.is_none());
        }
        for operation in ["empty-write", "flush", "shutdown"] {
            let (raw, _peer) = tokio::io::duplex(16);
            let mut stream = pending_status(
                Box::new(raw),
                Instant::now() + std::time::Duration::from_secs(1),
            );
            match operation {
                "empty-write" => assert_eq!(stream.write(&[]).await.unwrap(), 0),
                "flush" => stream.flush().await.unwrap(),
                "shutdown" => stream.shutdown().await.unwrap(),
                _ => unreachable!(),
            }
            assert!(stream.deadline.is_some(), "{operation}");
            assert_eq!(stream.read(&mut []).await.unwrap(), 0);
            tokio::time::advance(std::time::Duration::from_secs(2)).await;
            assert_eq!(
                stream.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert!(stream.raw.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn h2mux_upload_outlives_delayed_headers_and_validates_late_status() {
        for status in [Some(0), Some(1), Some(2), None] {
            let (raw, peer) = tokio::io::duplex(65536);
            let (accepted, mut requests) = tokio::sync::mpsc::channel(1);
            let peer_driver = tokio::spawn(async move {
                let mut connection = h2::server::handshake(peer).await.unwrap();
                while let Some(Ok(request)) = connection.accept().await {
                    if accepted.send(request).await.is_err() {
                        break;
                    }
                }
            });
            let (sender, driver) = h2_driver::new(Box::new(raw)).await.unwrap();
            let client_driver = tokio::spawn(driver);
            let deadline = Instant::now() + std::time::Duration::from_secs(10);
            let mut raw = Sender::H2(sender).open(deadline).await.unwrap();
            let metadata = [0, 0, 1, 192, 0, 2, 1, 1, 187];
            raw.write_all(&metadata).await.unwrap();
            raw.flush().await.unwrap();
            let (request, mut response) = requests.recv().await.unwrap();
            let mut input = request.into_body();
            let first = input.data().await.unwrap().unwrap();
            assert_eq!(first.as_ref(), metadata);
            input.flow_control().release_capacity(first.len()).unwrap();
            let mut stream = pending_status(raw, deadline);
            assert!(futures_util::poll!(std::pin::pin!(stream.read_u8())).is_pending());
            stream.write_all(b"before").await.unwrap();
            stream.flush().await.unwrap();
            let first = input.data().await.unwrap().unwrap();
            assert_eq!(first.as_ref(), b"before");
            input.flow_control().release_capacity(first.len()).unwrap();
            assert!(stream.deadline.is_none());

            tokio::time::advance(std::time::Duration::from_secs(11)).await;
            assert!(futures_util::poll!(std::pin::pin!(stream.read_u8())).is_pending());
            stream.write_all(b"after").await.unwrap();
            stream.flush().await.unwrap();
            let second = input.data().await.unwrap().unwrap();
            assert_eq!(second.as_ref(), b"after");
            input.flow_control().release_capacity(second.len()).unwrap();
            let mut output = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            match status {
                Some(status) => output
                    .send_data(Bytes::copy_from_slice(&[status, 42]), false)
                    .unwrap(),
                None => output.send_data(Bytes::new(), true).unwrap(),
            }
            if status == Some(0) {
                assert_eq!(stream.read_u8().await.unwrap(), 42);
                stream.shutdown().await.unwrap();
                while let Some(bytes) = input.data().await {
                    assert!(
                        bytes.unwrap().is_empty(),
                        "upload FIN must carry no extra payload"
                    );
                }
                output.send_data(Bytes::from_static(b"tail"), true).unwrap();
                let mut tail = Vec::new();
                stream.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, b"tail");
            } else {
                assert_eq!(
                    stream.read_u8().await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionRefused
                );
                assert!(stream.raw.is_none());
            }
            drop(stream);
            drop(input);
            drop(output);
            client_driver.abort();
            let _ = client_driver.await;
            peer_driver.abort();
            let _ = peer_driver.await;
        }
    }

    #[cfg(feature = "outbound-vless")]
    #[tokio::test(start_paused = true)]
    async fn brutal_control_reply_still_uses_the_original_setup_deadline() {
        let (raw, mut peer) = tokio::io::duplex(65536);
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer_observed = observed.clone();
        let peer_driver = tokio::spawn(async move {
            let mut protocol = [0; 2];
            peer.read_exact(&mut protocol).await.unwrap();
            assert_eq!(protocol, [0, 2]);
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let mut requests = tokio::task::JoinSet::new();
            while let Some(Ok((request, response))) = connection.accept().await {
                let observed = peer_observed.clone();
                requests.spawn(async move {
                    let mut input = request.into_body();
                    while let Some(Ok(bytes)) = input.data().await {
                        observed.store(true, Ordering::SeqCst);
                        input.flow_control().release_capacity(bytes.len()).unwrap();
                    }
                    drop(response);
                });
            }
            while let Some(result) = requests.join_next().await {
                result.unwrap();
            }
        });
        let config = crate::config::Config::parse_yaml(
            br#"proxies:
- name: edge
  type: vless
  server: example.test
  port: 443
  uuid: 07070707-0707-0707-0707-070707070707
  smux: {enabled: true, brutal-opts: {enabled: true, up: 8, down: 8}}
rules: ['MATCH,DIRECT']
"#,
        )
        .unwrap();
        let pool = Pool::new(config.proxies[0].smux.clone().unwrap());
        let start = Instant::now();
        let result = pool
            .open(
                &Destination::Ip("192.0.2.1:443".parse().unwrap()),
                false,
                start + std::time::Duration::from_secs(1),
                || async move {
                    Ok(SuppliedStream {
                        io: Box::new(raw),
                        #[cfg(target_os = "linux")]
                        control: None,
                    })
                },
            )
            .await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
        assert_eq!(Instant::now() - start, std::time::Duration::from_secs(1));
        assert!(observed.load(Ordering::SeqCst));
        pool.stop().await;
        peer_driver.await.unwrap();
    }
}
