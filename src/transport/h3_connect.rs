//! Shared HTTP/3 CONNECT sessions over supplied datagrams. Each protocol
//! chooses its admission, response and idle policy; the pool owns its tasks.
use crate::{
    dispatch::BoxStream,
    resources::observation::{self, ResourceKind},
    transport::{quic, quiche_h3},
};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const IDLE: Duration = Duration::from_secs(30);
const QUIC_IDLE: Duration = Duration::from_secs(74);
const CHUNK: usize = crate::transport::STREAM_CHUNK_BYTES;
type Sender = quiche_h3::Client;
type SendStream = quiche_h3::SendStream;
type RecvStream = quiche_h3::RecvStream;
type SendOperation = Pin<Box<dyn Future<Output = (SendHalf, io::Result<()>)> + Send + 'static>>;
type Observer = Arc<dyn Fn() + Send + Sync>;

pub(crate) use quiche_h3::Transport as QuicTransport;

#[cfg(feature = "outbound-masque")]
pub(crate) struct IpConnect {
    pub capsules: BoxStream,
    pub datagrams: IpDatagrams,
}

/// The associated request owns its lease. The IP engine owns this handle
/// together with that request and reads only its registered DATAGRAM flow.
pub(crate) struct IpDatagrams {
    connection: quiche_h3::Client,
    physical: Arc<Physical>,
    request_id: u64,
}

#[cfg(feature = "outbound-masque")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpDatagramSendError {
    TooLarge { packet_budget: usize },
    Closed,
}

#[cfg(feature = "outbound-masque")]
impl IpDatagrams {
    pub fn packet_budget(&self) -> usize {
        self.connection
            .max_datagram_size()
            .map_or(0, |maximum| self.packet_budget_from(maximum))
    }
    fn packet_budget_from(&self, maximum: usize) -> usize {
        maximum.saturating_sub(
            crate::transport::masque_codec::varint_len(self.request_id / 4).unwrap_or(8) + 1,
        )
    }
    /// Waits for actual path discovery without allocating another packet or
    /// task. The owner supplies its existing setup or packet deadline; an
    /// insufficient peer/path limit never becomes a fabricated usable MTU.
    pub async fn wait_packet_budget(&self, minimum: usize, deadline: Instant) -> io::Result<usize> {
        wait_for_packet_budget(&self.physical.cancel, minimum, deadline, || {
            self.connection
                .max_datagram_size()
                .map(|maximum| self.packet_budget_from(maximum))
        })
        .await
    }
    pub async fn send(&self, packet: &[u8]) -> Result<(), IpDatagramSendError> {
        if self.physical.cancel.is_cancelled() {
            return Err(IpDatagramSendError::Closed);
        }
        let maximum = self
            .connection
            .max_datagram_size()
            .ok_or(IpDatagramSendError::Closed)?;
        let packet_budget = self.packet_budget_from(maximum);
        if packet.len() > packet_budget {
            return Err(IpDatagramSendError::TooLarge { packet_budget });
        }
        let frame =
            crate::transport::masque_codec::encode_h3_datagram(self.request_id, packet, maximum)
                .map_err(|_| IpDatagramSendError::Closed)?;
        tokio::select! { biased;
            ()=self.physical.cancel.cancelled()=>Err(IpDatagramSendError::Closed),
            result=self.connection.send_datagram_wait(frame)=>match result {
                Ok(())=>Ok(()),
                Err(error) if error.kind() == io::ErrorKind::InvalidInput=>Err(IpDatagramSendError::TooLarge {
                    packet_budget:self.packet_budget(),
                }),
                Err(_)=>Err(IpDatagramSendError::Closed),
            },
        }
    }
    pub async fn receive(&self) -> io::Result<Bytes> {
        loop {
            let frame = tokio::select! { biased;
                ()=self.physical.cancel.cancelled()=>return Err(closed()),
                result=self.connection.read_datagram(self.request_id)=>result.map_err(|_|closed())?,
            };
            let Ok(packet) = crate::transport::masque_codec::decode_h3_datagram(
                &frame,
                self.request_id,
                frame.len(),
            ) else {
                continue;
            };
            let offset = frame.len() - packet.len();
            return Ok(frame.slice(offset..));
        }
    }
}

#[cfg(feature = "outbound-masque")]
async fn wait_for_packet_budget(
    cancel: &CancellationToken,
    minimum: usize,
    deadline: Instant,
    budget: impl Fn() -> Option<usize>,
) -> io::Result<usize> {
    let wait = async {
        loop {
            if cancel.is_cancelled() {
                return Err(closed());
            }
            let maximum = budget().ok_or_else(closed)?;
            if maximum >= minimum {
                return Ok(maximum);
            }
            // Poll the actual native path budget without assuming a probe succeeded.
            tokio::select! { biased;
                ()=cancel.cancelled()=>return Err(closed()),
                ()=tokio::time::sleep(Duration::from_millis(20))=>{},
            }
        }
    };
    timeout_at(deadline, wait)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[derive(Default)]
struct Usage {
    active: usize,
    idle_since: Option<Instant>,
    retiring: bool,
    closed: bool,
}
struct Physical {
    usage: Mutex<Usage>,
    connection: Mutex<Option<quiche_h3::Client>>,
    activity: Notify,
    cancel: CancellationToken,
    idle_timeout: Option<Duration>,
}
impl Physical {
    fn reserve(self: &Arc<Self>) -> io::Result<Lease> {
        let mut usage = self.usage.lock().unwrap();
        if usage.closed || usage.retiring || self.cancel.is_cancelled() {
            return Err(closed());
        }
        usage.active = usage
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        usage.idle_since = None;
        drop(usage);
        self.activity.notify_one();
        Ok(Lease(self.clone()))
    }
    fn is_closed(&self) -> bool {
        self.usage.lock().unwrap().closed || self.cancel.is_cancelled()
    }
    // The reservation and retirement decisions share this lock. Publishing
    // closed here precedes any later caller's attempt to reserve the session.
    fn retire_idle(&self, now: Instant) -> bool {
        let mut usage = self.usage.lock().unwrap();
        if usage.active == 0
            && (usage.retiring
                || self.idle_timeout.is_some_and(|timeout| {
                    usage.idle_since.is_some_and(|since| now >= since + timeout)
                }))
        {
            usage.closed = true;
            true
        } else {
            false
        }
    }
}
struct Lease(Arc<Physical>);
impl Drop for Lease {
    fn drop(&mut self) {
        let mut usage = self.0.usage.lock().unwrap();
        usage.active -= 1;
        if usage.active == 0 {
            usage.idle_since = Some(Instant::now());
        }
        drop(usage);
        self.0.activity.notify_one();
    }
}
struct Entry {
    sender: Sender,
    physical: Arc<Physical>,
    draining: bool,
}
impl Entry {
    fn retire(&mut self) {
        self.draining = true;
        self.physical.usage.lock().unwrap().retiring = true;
        self.physical.activity.notify_one();
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        // An unpublished Entry must promptly cancel its setup. Only the
        // explicit GOAWAY retirement of a published Entry preserves siblings.
        if !self.draining {
            self.physical.cancel.cancel();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    TrustTunnel,
    #[cfg(feature = "outbound-masque")]
    MasqueL4,
    #[cfg(feature = "outbound-masque")]
    MasqueIp,
}
impl Flavor {
    fn deferred(self) -> bool {
        self == Self::TrustTunnel
    }
    fn accepts(self, status: http::StatusCode) -> bool {
        if self.deferred() || self.ip() {
            status == 200
        } else {
            status.is_success()
        }
    }
    fn ip(self) -> bool {
        #[cfg(feature = "outbound-masque")]
        {
            self == Self::MasqueIp
        }
        #[cfg(not(feature = "outbound-masque"))]
        {
            false
        }
    }
}

pub(crate) struct Pool {
    connection: Arc<Mutex<Option<Entry>>>,
    opening: tokio::sync::Mutex<()>,
    admission: Mutex<()>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    congestion: Option<quiche::CongestionControlAlgorithm>,
    flavor: Flavor,
}
impl Pool {
    pub fn new(congestion: Option<quiche::CongestionControlAlgorithm>) -> Self {
        Self {
            connection: Arc::default(),
            opening: tokio::sync::Mutex::new(()),
            admission: Mutex::new(()),
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
            congestion,
            flavor: Flavor::TrustTunnel,
        }
    }
    #[cfg(feature = "outbound-masque")]
    pub fn masque_l4(congestion: Option<quiche::CongestionControlAlgorithm>) -> Self {
        let mut pool = Self::new(congestion);
        pool.flavor = Flavor::MasqueL4;
        pool
    }
    #[cfg(feature = "outbound-masque")]
    pub fn masque_ip(congestion: Option<quiche::CongestionControlAlgorithm>) -> Self {
        let mut pool = Self::new(congestion);
        pool.flavor = Flavor::MasqueIp;
        pool
    }
    // Managed tasks observe cancellation themselves, so their cleanup is
    // awaited rather than dropped by an outer cancellation select.
    fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) -> io::Result<()> {
        let _admission = self.admission.lock().unwrap();
        if self.cancellation.is_cancelled() {
            return Err(closed());
        }
        self.tasks.spawn(observation::task(future));
        Ok(())
    }
    pub async fn open_connect<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        observer: Option<Observer>,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
    {
        self.open(request, deadline, observer, connect)
            .await
            .map(|(stream, _)| stream)
    }
    #[cfg(feature = "outbound-masque")]
    pub async fn open_ip_connect<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        connect: F,
    ) -> io::Result<IpConnect>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
    {
        let (capsules, datagrams) = self.open(request, deadline, None, connect).await?;
        Ok(IpConnect {
            capsules,
            datagrams: datagrams.ok_or_else(closed)?,
        })
    }
    async fn open<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        observer: Option<Observer>,
        connect: F,
    ) -> io::Result<(BoxStream, Option<IpDatagrams>)>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
    {
        let operation = async {
            let _waiter = observation::track(ResourceKind::Waiter);
            let (mut sender, lease) = self.acquire(deadline, connect).await?;
            let request = sender.send_request(request).await.map_err(|error| {
                retire_on_connection_error(&lease, &error);
                closed()
            })?;
            let datagrams = if self.flavor.ip() {
                lease
                    .0
                    .connection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(closed)?
                    .register_datagrams(request.id().into_inner())?;
                Some(IpDatagrams {
                    connection: lease
                        .0
                        .connection
                        .lock()
                        .unwrap()
                        .as_ref()
                        .cloned()
                        .ok_or_else(closed)?,
                    physical: lease.0.clone(),
                    request_id: request.id().into_inner(),
                })
            } else {
                None
            };
            let (send, receive) = request.split();
            let close = Arc::new(Close::default());
            let (ready, response) = oneshot::channel();
            let cancellation = self.cancellation.clone();
            let headers_close = close.clone();
            let headers_physical = lease.0.clone();
            let flavor = self.flavor;
            self.spawn(async move {
                let mut receive = ReceiveHalf(receive);
                let result = tokio::select! {biased;
                    ()=cancellation.cancelled()=>Err(closed()),
                    ()=headers_close.cancel.cancelled()=>Err(closed()),
                    ()=headers_physical.cancel.cancelled()=>Err(closed()),
                    response=receive.0.recv_response()=>response
                        .map_err(|error| { retire_physical(&headers_physical, &error); closed() })
                        .and_then(|response|if flavor.accepts(response.status()) {Ok(())} else {Err(closed())}),
                };
                if result.is_ok() {
                    if let Some(observer) = observer {
                        observer();
                    }
                } else {
                    headers_close.stop(true);
                }
                let _ = ready.send(result.map(|()| receive));
            })?;
            let mut stream = Stream {
                response: Some(response),
                receive: None,
                send: Some(SendHalf { stream: send }),
                pending: None,
                data: Bytes::new(),
                close,
                lease: Some(lease),
                finishing: false,
                finished: false,
                _observation: observation::track(ResourceKind::Session),
            };
            if !self.flavor.deferred() {
                let receive = stream
                    .response
                    .take()
                    .unwrap()
                    .await
                    .map_err(|_| closed())??;
                stream.receive = Some(receive);
            }
            Ok((Box::new(stream) as BoxStream, datagrams))
        };
        tokio::select! {biased;
            ()=self.cancellation.cancelled()=>Err(closed()),
            result=timeout_at(deadline,operation)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
    pub async fn probe<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        connect: F,
    ) -> io::Result<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
    {
        let operation = async {
            let _waiter = observation::track(ResourceKind::Waiter);
            let (mut sender, lease) = self.acquire(deadline, connect).await?;
            let request = sender.send_request(request).await.map_err(|error| {
                retire_on_connection_error(&lease, &error);
                closed()
            })?;
            let (send, receive) = request.split();
            let mut send = SendHalf { stream: send };
            let mut receive = ReceiveHalf(receive);
            // A probe has no body. FIN is required; ordinary business CONNECT
            // leaves its upload open for the initial client-first bytes.
            send.stream.finish().await.map_err(|_| closed())?;
            let response = receive.0.recv_response().await.map_err(|_| closed())?;
            if response.status() == 200 {
                Ok(())
            } else {
                Err(closed())
            }
        };
        tokio::select! {biased;
            ()=self.cancellation.cancelled()=>Err(closed()),
            result=timeout_at(deadline,operation)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
    async fn acquire<F, Fut>(&self, deadline: Instant, connect: F) -> io::Result<(Sender, Lease)>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
    {
        let _opening = self.opening.lock().await;
        {
            let _admission = self.admission.lock().unwrap();
            if self.cancellation.is_cancelled() {
                return Err(closed());
            }
            let mut current = self.connection.lock().unwrap();
            if let Some(entry) = current.as_mut() {
                let available = entry.sender.can_open_request();
                if !available {
                    entry.retire();
                }
                match available.then(|| entry.physical.reserve()) {
                    Some(Ok(lease)) => return Ok((entry.sender.clone(), lease)),
                    Some(Err(error)) if error.kind() != io::ErrorKind::ConnectionAborted => {
                        return Err(error);
                    }
                    _ => {}
                }
                current.take();
            }
        }
        let cancel = self.cancellation.child_token();
        let physical = Arc::new(Physical {
            usage: Mutex::new(Usage {
                idle_since: Some(Instant::now()),
                ..Default::default()
            }),
            connection: Mutex::new(None),
            activity: Notify::new(),
            cancel,
            idle_timeout: self.flavor.deferred().then_some(IDLE),
        });
        let (ready, response) = oneshot::channel();
        let congestion = self.congestion;
        let registry = Arc::downgrade(&self.connection);
        self.spawn(drive(
            connect,
            deadline,
            physical.clone(),
            registry,
            congestion,
            self.flavor,
            ready,
        ))?;
        let mut setup = SetupCancel(Some(physical.cancel.clone()));
        let entry = response.await.map_err(|_| closed())??;
        let _admission = self.admission.lock().unwrap();
        if self.cancellation.is_cancelled() {
            return Err(closed());
        }
        let lease = entry.physical.reserve()?;
        let sender = entry.sender.clone();
        *self.connection.lock().unwrap() = Some(entry);
        setup.0.take();
        Ok((sender, lease))
    }
    pub fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancellation.cancel();
        self.tasks.close();
    }
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
        self.connection.lock().unwrap().take();
    }
}
struct SetupCancel(Option<CancellationToken>);
impl Drop for SetupCancel {
    fn drop(&mut self) {
        if let Some(cancel) = &self.0 {
            cancel.cancel();
        }
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

async fn drive<F, Fut>(
    connect: F,
    deadline: Instant,
    physical: Arc<Physical>,
    registry: Weak<Mutex<Option<Entry>>>,
    congestion: Option<quiche::CongestionControlAlgorithm>,
    flavor: Flavor,
    ready: oneshot::Sender<io::Result<Entry>>,
) where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
{
    let mut ready = Some(ready);
    let raw = tokio::select! {biased;
        () = physical.cancel.cancelled() => Err(closed()),
        result = timeout_at(deadline, connect()) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut)).and_then(|result| result),
    };
    let mut pool_observation = None;
    if let Ok(raw) = raw {
        let options = quiche_h3::Options {
            idle: if flavor.deferred() {
                QUIC_IDLE
            } else {
                Duration::from_secs(74)
            },
            keepalive: (!flavor.deferred()).then_some(Duration::from_secs(30)),
            datagrams: flavor.ip(),
            congestion: congestion.unwrap_or(quiche::CongestionControlAlgorithm::CUBIC),
            ..Default::default()
        };
        match quiche_h3::Driver::new(raw, options).await {
            Ok((sender, driver)) => {
                let driver_cancel = CancellationToken::new();
                let driver = driver.run(driver_cancel.clone());
                tokio::pin!(driver);
                let mut driver_finished = false;
                let setup = tokio::select! {biased;
                    () = physical.cancel.cancelled() => Err(closed()),
                    _ = &mut driver => { driver_finished = true; Err(closed()) },
                    result = timeout_at(deadline, sender.ready(flavor.ip())) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut)).and_then(|result| result),
                };
                if let Err(error) = setup {
                    let _ = ready.take().unwrap().send(Err(error));
                } else {
                    *physical.connection.lock().unwrap() = Some(sender.clone());
                    pool_observation = Some(observation::track(ResourceKind::Pool));
                    if ready
                        .take()
                        .unwrap()
                        .send(Ok(Entry {
                            sender,
                            physical: physical.clone(),
                            draining: false,
                        }))
                        .is_err()
                    {
                        physical.cancel.cancel();
                    }
                    loop {
                        let activity = physical.activity.notified();
                        if physical.retire_idle(Instant::now()) {
                            break;
                        }
                        let expires = physical
                            .usage
                            .lock()
                            .unwrap()
                            .idle_since
                            .zip(physical.idle_timeout)
                            .map(|(since, timeout)| since + timeout);
                        tokio::select! {biased;
                            () = physical.cancel.cancelled() => break,
                            _ = &mut driver => { driver_finished = true; break; },
                            () = activity => {},
                            () = async { match expires { Some(deadline) => tokio::time::sleep_until(deadline).await, None => std::future::pending().await } } => { if physical.retire_idle(Instant::now()) { break; } },
                        }
                    }
                }
                driver_cancel.cancel();
                if !driver_finished {
                    let _ = driver.await;
                }
            }
            Err(error) => {
                let _ = ready.take().unwrap().send(Err(error));
            }
        }
    } else if let Err(error) = raw {
        let _ = ready.take().unwrap().send(Err(error));
    }
    physical.usage.lock().unwrap().closed = true;
    physical.cancel.cancel();
    physical.connection.lock().unwrap().take();
    if let Some(registry) = registry.upgrade() {
        let mut current = registry.lock().unwrap();
        if current
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(&entry.physical, &physical))
        {
            current.take();
        }
    }
    drop(pool_observation);
}

fn retire_on_connection_error(lease: &Lease, error: &io::Error) {
    retire_physical(&lease.0, error);
}
fn retire_physical(physical: &Physical, _: &io::Error) {
    // h3's default stable API deliberately hides its internal error variants.
    // A stream error alone must not abort its siblings. The public QUIC state
    // identifies actual physical closure; the control driver retires H3 errors.
    if physical
        .connection
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|connection| connection.close_reason().is_some())
    {
        physical.usage.lock().unwrap().closed = true;
        physical.cancel.cancel();
    }
}
fn closed() -> io::Error {
    io::Error::from(io::ErrorKind::ConnectionAborted)
}

#[derive(Default)]
struct Close {
    stopped: AtomicBool,
    failed: AtomicBool,
    reader: AtomicWaker,
    writer: AtomicWaker,
    cancel: CancellationToken,
}
impl Close {
    fn stop(&self, failed: bool) {
        if failed {
            self.failed.store(true, Ordering::Release);
        }
        self.stopped.store(true, Ordering::Release);
        self.cancel.cancel();
        self.reader.wake();
        self.writer.wake();
    }
}
struct SendHalf {
    stream: SendStream,
}
impl Drop for SendHalf {
    fn drop(&mut self) {
        self.stream.stop_stream(quiche_h3::REQUEST_CANCELLED);
    }
}
struct ReceiveHalf(RecvStream);
impl Drop for ReceiveHalf {
    fn drop(&mut self) {
        self.0.stop_sending(quiche_h3::REQUEST_CANCELLED);
    }
}
struct Stream {
    response: Option<oneshot::Receiver<io::Result<ReceiveHalf>>>,
    receive: Option<ReceiveHalf>,
    send: Option<SendHalf>,
    // This future owns the send half and at most one CHUNK. Returning accepted
    // bytes immediately makes cancellation/re-polling unable to duplicate DATA.
    pending: Option<SendOperation>,
    data: Bytes,
    close: Arc<Close>,
    lease: Option<Lease>,
    finishing: bool,
    finished: bool,
    _observation: observation::Guard,
}
impl Stream {
    fn stopped(&self) -> bool {
        self.close.stopped.load(Ordering::Acquire)
            || self.lease.as_ref().is_none_or(|lease| lease.0.is_closed())
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close.writer.register(cx.waker());
        self.progress(cx)
    }
    fn progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stopped() {
            return Poll::Ready(Err(closed()));
        }
        if let Some(pending) = &mut self.pending {
            let (send, result) = ready!(pending.as_mut().poll(cx));
            self.pending = None;
            self.send = Some(send);
            if result.is_err() {
                self.close.stop(true);
            }
            result?;
        }
        Poll::Ready(Ok(()))
    }
    fn end(&mut self) {
        self.close.stop(false);
        self.response = None;
        self.receive = None;
        self.pending = None;
        self.send = None;
        self.data = Bytes::new();
        self.lease.take();
        self.finished = true;
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.end();
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.close.reader.register(cx.waker());
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.stopped() {
            return Poll::Ready(Err(closed()));
        }
        // A caller may write once and then read without flushing. Advance the
        // accepted DATA with this read's waker, but do not gate reading on send
        // credit: the peer's response can be needed to release that credit.
        if let Poll::Ready(Err(error)) = self.progress(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(response) = &mut self.response {
            let received = ready!(Pin::new(response).poll(cx)).map_err(|_| closed())??;
            self.response = None;
            self.receive = Some(received);
        }
        // Limit control-frame/data work per poll, just as shared stream IO does.
        for _ in 0..32 {
            if !self.data.is_empty() {
                let count = self.data.len().min(buffer.remaining());
                buffer.put_slice(&self.data[..count]);
                self.data.advance(count);
                return Poll::Ready(Ok(()));
            }
            let Some(receive) = self.receive.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match ready!(receive.0.poll_recv_data(cx)) {
                Ok(Some(mut data)) => self.data = data.copy_to_bytes(data.remaining()),
                Ok(None) => {
                    self.receive = None;
                    return Poll::Ready(Ok(()));
                }
                Err(error) => {
                    if let Some(lease) = &self.lease {
                        retire_on_connection_error(lease, &error);
                    }
                    self.close.stop(true);
                    return Poll::Ready(Err(closed()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.finishing || self.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(CHUNK);
        let bytes = Bytes::copy_from_slice(&input[..count]);
        let mut send = self.send.take().unwrap();
        self.pending = Some(Box::pin(async move {
            let result = send.stream.send_data(bytes).await.map_err(|_| closed());
            (send, result)
        }));
        if let Poll::Ready(Err(error)) = self.progress(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        self.drain(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(Err(error)) = self.drain(cx) {
            self.end();
            return Poll::Ready(Err(error));
        }
        if self.pending.is_some() {
            return Poll::Pending;
        }
        if !self.finishing {
            self.finishing = true;
            let mut send = self.send.take().unwrap();
            self.pending = Some(Box::pin(async move {
                let result = tokio::time::timeout(quic::CLOSE_TIMEOUT, send.stream.finish())
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
                    .and_then(|result| result.map_err(|_| closed()));
                (send, result)
            }));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.end();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dispatch::{DatagramBudget, DatagramTransport, DispatchError},
        resources::observation::ResourceProbe,
        session::{Datagram, Destination},
    };
    use async_trait::async_trait;
    use std::{io::IoSliceMut, net::SocketAddr, sync::atomic::AtomicUsize};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
    };

    #[cfg(feature = "outbound-masque")]
    #[tokio::test(start_paused = true)]
    async fn masque_ip_budget_wait_observes_growth_and_enforces_stop_and_deadline() {
        let cancel = CancellationToken::new();
        let maximum = AtomicUsize::new(1198);
        let deadline = Instant::now() + Duration::from_secs(2);
        let wait = wait_for_packet_budget(&cancel, 1280, deadline, || {
            Some(maximum.load(Ordering::Acquire))
        });
        tokio::pin!(wait);
        tokio::select! { biased;
            result=&mut wait=>panic!("insufficient budget became ready: {result:?}"),
            ()=tokio::time::sleep(Duration::from_millis(40))=>{},
        }
        maximum.store(1300, Ordering::Release);
        assert_eq!(wait.await.unwrap(), 1300);

        let deadline = Instant::now() + Duration::from_millis(50);
        let error = wait_for_packet_budget(&cancel, 1280, deadline, || Some(1198))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        cancel.cancel();
        let error = wait_for_packet_budget(
            &cancel,
            1280,
            Instant::now() + Duration::from_secs(2),
            || Some(1400),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[derive(Clone, Copy)]
    enum PacketInput {
        Unique,
        OwnerBacked,
    }
    struct Packets {
        input: PacketInput,
        send: mpsc::Sender<Bytes>,
        receive: mpsc::Receiver<Bytes>,
        peer: SocketAddr,
        closed: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl DatagramTransport for Packets {
        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            DatagramBudget::new(1400, 1400)
        }
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            assert_eq!(datagram.remote, Destination::Ip(self.peer));
            self.send
                .send(datagram.payload)
                .await
                .map_err(|_| DispatchError::NotAllowed)
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            let payload = self.receive.recv().await.ok_or(DispatchError::NotAllowed)?;
            let payload = match self.input {
                PacketInput::Unique => payload,
                // from_owner stays immutable even if its inner Bytes later
                // becomes unique while the adapter prefetches more packets.
                PacketInput::OwnerBacked => Bytes::from_owner(payload),
            };
            Ok(Datagram {
                remote: Destination::Ip(self.peer),
                payload,
                sniffed_domain: None,
            })
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closed.fetch_add(1, Ordering::AcqRel);
            self.receive.close();
            Ok(())
        }
    }
    #[derive(Debug)]
    struct Socket {
        send: mpsc::Sender<Bytes>,
        receive: Mutex<mpsc::Receiver<Bytes>>,
        peer: SocketAddr,
        local: SocketAddr,
    }
    #[derive(Debug)]
    struct Writable(Mutex<tokio_util::sync::PollSender<Bytes>>);
    impl quinn::UdpPoller for Writable {
        fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut sender = self.0.lock().unwrap();
            if ready!(sender.poll_reserve(cx)).is_ok() {
                sender.abort_send();
            }
            Poll::Ready(Ok(()))
        }
    }
    impl quinn::AsyncUdpSocket for Socket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
            Box::pin(Writable(Mutex::new(tokio_util::sync::PollSender::new(
                self.send.clone(),
            ))))
        }
        fn try_send(&self, datagram: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            assert_eq!(datagram.destination, self.peer);
            match self
                .send
                .try_send(Bytes::copy_from_slice(datagram.contents))
            {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            buffers: &mut [IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let Some(packet) = ready!(self.receive.lock().unwrap().poll_recv(cx)) else {
                return Poll::Pending;
            };
            buffers[0][..packet.len()].copy_from_slice(&packet);
            meta[0] = quinn::udp::RecvMeta {
                addr: self.peer,
                len: packet.len(),
                stride: packet.len(),
                ecn: None,
                dst_ip: Some(self.local.ip()),
            };
            Poll::Ready(Ok(1))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local)
        }
    }
    const LARGE_DUPLEX_BYTES: usize = 512 * 1024;

    struct Peer {
        client: crate::security::StandardTlsClient,
        server: rustls::ServerConfig,
        cancel: CancellationToken,
        tasks: TaskTracker,
        calls: AtomicUsize,
        closed: Arc<AtomicUsize>,
        checks: AtomicUsize,
        reject: Arc<Notify>,
        goaway: Notify,
        duplex_fin: Mutex<Option<oneshot::Sender<io::Result<usize>>>>,
        input: PacketInput,
        l4: bool,
    }
    impl Peer {
        fn new() -> Arc<Self> {
            let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(identity.cert.der().clone()).unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let client = crate::security::StandardTlsClient::with_options(
                &crate::security::SecurityContext::with_tls_roots(roots),
                "localhost",
                crate::security::TlsClientOptions {
                    alpn: vec![b"h3".to_vec()],
                    required_alpn: Some(b"h3".to_vec()),
                    versions: crate::security::TlsVersions::Tls13,
                    ..Default::default()
                },
                0,
                64 * 1024,
            )
            .unwrap();
            let mut server = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![identity.cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        identity.signing_key.serialize_der().into(),
                    ),
                )
                .unwrap();
            server.alpn_protocols = vec![b"h3".to_vec()];
            Arc::new(Self {
                client,
                server,
                cancel: CancellationToken::new(),
                tasks: TaskTracker::new(),
                calls: AtomicUsize::new(0),
                closed: Arc::new(AtomicUsize::new(0)),
                checks: AtomicUsize::new(0),
                reject: Arc::new(Notify::new()),
                goaway: Notify::new(),
                duplex_fin: Mutex::new(None),
                input: PacketInput::Unique,
                l4: false,
            })
        }
        #[cfg(feature = "outbound-masque")]
        fn l4() -> Arc<Self> {
            let mut peer = Self::new();
            Arc::get_mut(&mut peer).unwrap().l4 = true;
            peer
        }
        async fn connect(self: Arc<Self>) -> io::Result<QuicTransport> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let local: SocketAddr = "192.0.2.1:443".parse().unwrap();
            let peer: SocketAddr = "192.0.2.2:41000".parse().unwrap();
            let (to_client, from_server) = mpsc::channel(32);
            let (to_server, from_client) = mpsc::channel(32);
            let socket = Arc::new(Socket {
                send: to_client,
                receive: Mutex::new(from_client),
                local,
                peer,
            });
            let crypto =
                quinn::crypto::rustls::QuicServerConfig::try_from(self.server.clone()).unwrap();
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .mtu_discovery_config(None)
                .stream_receive_window(1024_u32.into());
            let runtime = Arc::new(quic::OwnedRuntime::new(CancellationToken::new()));
            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(config),
                socket,
                runtime.clone(),
            )
            .unwrap();
            let owner = self.clone();
            self.tasks.spawn(async move {
                let serve=async {
                    let connected=endpoint.accept().await.unwrap().await.unwrap();
                    let mut connection=h3::server::builder().build::<_,Bytes>(h3_quinn::Connection::new(connected)).await.unwrap();
                    loop {
                        let request = tokio::select! {
                            ()=owner.goaway.notified()=>{
                                connection.shutdown(0).await.unwrap();
                                continue;
                            },
                            result=connection.accept()=>match result {
                                Ok(Some(request))=>request,
                                _=>break,
                            }
                        };
                        let (request,mut stream)=request.resolve_request().await.unwrap();
                        assert_eq!(request.method(),http::Method::CONNECT);
                        assert!(request.uri().scheme().is_none());
                        assert!(request.uri().path_and_query().is_none());
                        if owner.l4 {
                            assert!(!request.headers().contains_key("proxy-authorization"));
                        } else {
                            assert_eq!(request.headers()["proxy-authorization"],"Basic dTpw");
                        }
                        let target=request.uri().authority().unwrap().as_str().to_owned();
                        let handler=owner.clone();
                        owner.tasks.spawn(async move {
                            let handle=async {
                                if target=="_check" {
                                    assert!(stream.recv_data().await.unwrap().is_none());
                                    stream.send_response(http::Response::new(())).await.unwrap();
                                    stream.finish().await.unwrap();
                                    handler.checks.fetch_add(1,Ordering::AcqRel);
                                } else if target=="reject.invalid:443" {
                                    if !handler.l4 { handler.reject.notified().await; }
                                    stream.send_response(http::Response::builder().status(407).body(()).unwrap()).await.unwrap();
                                    stream.finish().await.unwrap();
                                } else if target=="large-duplex.invalid:443" {
                                    let witness=handler.duplex_fin.lock().unwrap().take().unwrap();
                                    let result=async {
                                        let (mut send,mut receive)=stream.split();
                                        let mut received=0;
                                        while let Some(mut data)=receive.recv_data().await.map_err(|error|io::Error::other(error.to_string()))? {
                                            let data=data.copy_to_bytes(data.remaining());
                                            if data.is_empty() {continue;}
                                            if data.len()>LARGE_DUPLEX_BYTES-received || data.iter().enumerate().any(|(index,byte)|*byte!=((received+index) as u8).wrapping_mul(31).wrapping_add(7)) {
                                                return Err(io::Error::other("large duplex peer payload mismatch"));
                                            }
                                            if received==0 {send.send_response(http::Response::new(())).await.map_err(|error|io::Error::other(error.to_string()))?;}
                                            received+=data.len();
                                            send.send_data(data).await.map_err(|error|io::Error::other(error.to_string()))?;
                                            if received==LARGE_DUPLEX_BYTES {send.finish().await.map_err(|error|io::Error::other(error.to_string()))?;}
                                        }
                                        // recv_data(None) is the peer's real request FIN witness.
                                        if received!=LARGE_DUPLEX_BYTES {return Err(io::Error::other("large duplex peer received a short body"));}
                                        Ok::<_,io::Error>(received)
                                    }.await;
                                    let _=witness.send(result);
                                } else {
                                    if handler.l4 {
                                        stream.send_response(http::Response::builder().status(204).body(()).unwrap()).await.unwrap();
                                    }
                                    let first=stream.recv_data().await.unwrap().unwrap();
                                    let mut first=first;
                                    let first=first.copy_to_bytes(first.remaining());
                                    if !handler.l4 { stream.send_response(http::Response::new(())).await.unwrap(); }
                                    stream.send_data(first).await.unwrap();
                                    while let Ok(Some(mut data))=stream.recv_data().await {
                                        let data=data.copy_to_bytes(data.remaining());
                                        if stream.send_data(data).await.is_err() {break;}
                                    }
                                    let _=stream.finish().await;
                                }
                            };
                            tokio::select! {biased; ()=handler.cancel.cancelled()=>{}, ()=handle=>{}}
                        });
                    }
                };
                tokio::select! {biased; ()=owner.cancel.cancelled()=>{}, ()=serve=>{}}
                endpoint.close(0_u8.into(),b"");
                runtime.stop().await;
            });
            Ok(QuicTransport {
                transport: Box::new(Packets {
                    input: self.input,
                    send: to_server,
                    receive: from_server,
                    peer: local,
                    closed: self.closed.clone(),
                }),
                peer: local,
                budget: DatagramBudget::new(1400, 1400),
                tls: self.client.quiche_config()?,
                server_name: "localhost".into(),
            })
        }
        async fn stop(&self) {
            self.cancel.cancel();
            self.tasks.close();
            self.tasks.wait().await;
        }
    }
    fn request(target: &str) -> http::Request<()> {
        http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(http::Uri::builder().authority(target).build().unwrap())
            .header("proxy-authorization", "Basic dTpw")
            .header("user-agent", "memory")
            .body(())
            .unwrap()
    }
    async fn open(pool: &Pool, peer: &Arc<Peer>, target: &str) -> BoxStream {
        let peer = peer.clone();
        pool.open_connect(
            request(target),
            Instant::now() + Duration::from_secs(5),
            None,
            move || peer.connect(),
        )
        .await
        .unwrap()
    }
    async fn echo(stream: &mut BoxStream, data: &[u8]) {
        stream.write_all(data).await.unwrap();
        // No flush: a single client-first write followed by a read must move
        // DATA even though both protocol halves share this byte-stream owner.
        let mut response = vec![0; data.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, data);
    }
    #[cfg(feature = "outbound-masque")]
    #[tokio::test]
    async fn masque_l4_waits_for_2xx_and_rejection_keeps_independent_sibling_alive() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peer = Peer::l4();
                let pool = Pool::masque_l4(None);
                let open = |target: &str| {
                    let factory = peer.clone();
                    let request = http::Request::builder()
                        .method(http::Method::CONNECT)
                        .uri(http::Uri::builder().authority(target).build().unwrap())
                        .body(())
                        .unwrap();
                    pool.open_connect(
                        request,
                        Instant::now() + Duration::from_secs(3),
                        None,
                        move || factory.connect(),
                    )
                };
                let mut first = open("echo.invalid:443").await.unwrap();
                // The peer sends 204 before any DATA: a deferred or 200-only
                // implementation would hang or reject this actual CONNECT stream.
                let mut second = open("echo.invalid:443").await.unwrap();
                echo(&mut first, b"first").await;
                echo(&mut second, b"second").await;
                assert!(open("reject.invalid:443").await.is_err());
                echo(&mut second, b"after-rejection").await;
                first.shutdown().await.unwrap();
                echo(&mut second, b"after-close").await;
                assert_eq!(peer.calls.load(Ordering::Acquire), 1);
                let physical = pool
                    .connection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .physical
                    .clone();
                assert!(physical.idle_timeout.is_none());
                pool.shutdown().await;
                assert!(second.write_all(b"after-stop").await.is_err());
                assert!(open("echo.invalid:443").await.is_err());
                assert_eq!(peer.calls.load(Ordering::Acquire), 1);
                drop((first, second, pool, physical));
                peer.stop().await;
                assert_eq!(peer.closed.load(Ordering::Acquire), 1);
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }
    #[tokio::test]
    async fn trusttunnel_h3_deferred_headers_share_streams_probe_and_join_stop() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peer = Peer::new();
                let pool = Pool::new(quiche_h3::congestion_controller("bbr", 0, "standard"));
                let mut first = open(&pool, &peer, "echo.invalid:443").await;
                let mut second = open(&pool, &peer, "echo.invalid:443").await;
                assert_eq!(peer.calls.load(Ordering::Acquire), 1);
                echo(&mut first, b"client-first").await;
                echo(&mut second, b"second").await;
                first.shutdown().await.unwrap();
                echo(&mut second, b"survives-sibling-close").await;
                let factory = peer.clone();
                pool.probe(
                    request("_check"),
                    Instant::now() + Duration::from_secs(7),
                    move || factory.connect(),
                )
                .await
                .unwrap();
                assert_eq!(peer.checks.load(Ordering::Acquire), 1);
                assert_eq!(
                    pool.connection
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .physical
                        .usage
                        .lock()
                        .unwrap()
                        .active,
                    1
                );
                pool.shutdown().await;
                assert!(second.write_all(b"after-stop").await.is_err());
                let calls = peer.calls.load(Ordering::Acquire);
                let factory = peer.clone();
                assert!(
                    pool.probe(
                        request("_check"),
                        Instant::now() + Duration::from_secs(7),
                        move || factory.connect()
                    )
                    .await
                    .is_err()
                );
                assert_eq!(peer.calls.load(Ordering::Acquire), calls);
                drop((first, second, pool));
                peer.stop().await;
                assert_eq!(peer.closed.load(Ordering::Acquire), 1);
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }
    #[tokio::test]
    async fn trusttunnel_h3_large_duplex_data_fin_and_joined_stop() {
        large_duplex_ingress(PacketInput::Unique).await;
    }
    #[tokio::test]
    async fn quiche_h3_owner_backed_ingress_preserves_duplex_fin_and_joined_stop() {
        large_duplex_ingress(PacketInput::OwnerBacked).await;
    }
    async fn large_duplex_ingress(input: PacketInput) {
        use futures_util::FutureExt;
        use std::panic::{AssertUnwindSafe, resume_unwind};

        let observation = ResourceProbe::default();
        let (result, cleanup, calls, closed, empty) = observation
            .scope(async {
                let mut peer = Peer::new();
                Arc::get_mut(&mut peer).unwrap().input = input;
                let pool = Pool::new(None);
                let (finished, fin) = oneshot::channel();
                *peer.duplex_fin.lock().unwrap() = Some(finished);
                let result =
                    AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(15), async {
                        let stream = open(&pool, &peer, "large-duplex.invalid:443").await;
                        let (mut read, mut write) = tokio::io::split(stream);
                        let payload = (0..LARGE_DUPLEX_BYTES)
                            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
                            .collect::<Vec<_>>();
                        let read_complete = Notify::new();
                        let upload = async {
                            write.write_all(&payload).await?;
                            write.flush().await?;
                            // Shutdown ends this whole logical CONNECT stream; keep
                            // the reader alive until the concurrent echo is complete.
                            read_complete.notified().await;
                            write.shutdown().await
                        };
                        let download = async {
                            let mut echoed = vec![0; LARGE_DUPLEX_BYTES];
                            read.read_exact(&mut echoed).await?;
                            if echoed != payload {
                                return Err(io::Error::other(
                                    "large duplex client payload mismatch",
                                ));
                            }
                            let mut extra = [0];
                            if read.read(&mut extra).await? != 0 {
                                return Err(io::Error::other(
                                    "large duplex response exceeded its body",
                                ));
                            }
                            read_complete.notify_one();
                            Ok::<_, io::Error>(())
                        };
                        tokio::try_join!(upload, download)?;
                        let received = fin.await.map_err(|_| {
                            io::Error::other("large duplex peer did not report FIN")
                        })??;
                        if received != LARGE_DUPLEX_BYTES {
                            return Err(io::Error::other(
                                "large duplex FIN witness had a short body",
                            ));
                        }
                        Ok::<_, io::Error>(())
                    }))
                    .catch_unwind()
                    .await;
                // Always join the owned client and memory peer before exposing
                // the operation's timeout, IO error, or panic to the test runner.
                let cleanup = tokio::time::timeout(Duration::from_secs(5), async {
                    pool.shutdown().await;
                    peer.stop().await;
                })
                .await;
                let calls = peer.calls.load(Ordering::Acquire);
                let closed = peer.closed.load(Ordering::Acquire);
                let empty = pool.tasks.is_empty() && peer.tasks.is_empty();
                drop((pool, peer));
                (result, cleanup, calls, closed, empty)
            })
            .await;
        let result = match result {
            Ok(result) => result,
            Err(panic) => resume_unwind(panic),
        };
        cleanup.expect("large duplex Stop did not join within its bound");
        assert!(empty);
        assert_eq!(calls, 1);
        assert_eq!(closed, 1);
        assert!(observation.snapshot().is_idle());
        result
            .expect("large duplex DATA/FIN timed out")
            .expect("large duplex DATA/FIN failed");
    }
    #[tokio::test]
    async fn trusttunnel_h3_rejected_headers_wake_stalled_write_without_read() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peer = Peer::new();
                let pool = Pool::new(None);
                let mut stream = open(&pool, &peer, "reject.invalid:443").await;
                let bytes = vec![1; 256 * 1024];
                let blocked = stream.write_all(&bytes);
                let mut blocked = Box::pin(blocked);
                tokio::select! {
                    result=&mut blocked=>panic!("write completed before rejection: {result:?}"),
                    ()=tokio::time::sleep(Duration::from_millis(20))=>{},
                }
                peer.reject.notify_one();
                assert!(
                    tokio::time::timeout(Duration::from_secs(2), &mut blocked)
                        .await
                        .unwrap()
                        .is_err()
                );
                drop(blocked);
                pool.shutdown().await;
                drop(stream);
                peer.stop().await;
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }
    #[tokio::test(start_paused = true)]
    async fn trusttunnel_h3_idle_session_retires_and_next_request_reconnects() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peer = Peer::new();
                let pool = Pool::new(None);
                let mut first = open(&pool, &peer, "echo.invalid:443").await;
                echo(&mut first, b"before-idle").await;
                first.shutdown().await.unwrap();
                drop(first);
                tokio::time::advance(IDLE + Duration::from_secs(1)).await;
                tokio::time::timeout(Duration::from_secs(3), async {
                    while peer.closed.load(Ordering::Acquire) == 0 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
                let mut second = open(&pool, &peer, "echo.invalid:443").await;
                echo(&mut second, b"after-idle").await;
                assert_eq!(peer.calls.load(Ordering::Acquire), 2);
                pool.shutdown().await;
                drop((second, pool));
                peer.stop().await;
                assert_eq!(peer.closed.load(Ordering::Acquire), 2);
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }
    #[tokio::test]
    async fn trusttunnel_h3_goaway_reconnects_without_cancelling_accepted_sibling() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peer = Peer::new();
                let pool = Pool::new(None);
                let mut first = open(&pool, &peer, "echo.invalid:443").await;
                echo(&mut first, b"before-goaway").await;
                peer.goaway.notify_one();
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if !pool
                            .connection
                            .lock()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .sender
                            .can_open_request()
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let mut second = open(&pool, &peer, "echo.invalid:443").await;
                assert_eq!(peer.calls.load(Ordering::Acquire), 2);
                assert_eq!(observation.snapshot().current(ResourceKind::Pool), 2);
                echo(&mut first, b"old-accepted-stream-survives").await;
                echo(&mut second, b"new-session").await;
                first.shutdown().await.unwrap();
                drop(first);
                tokio::time::timeout(Duration::from_secs(3), async {
                    while peer.closed.load(Ordering::Acquire) == 0 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
                echo(&mut second, b"after-old-session-retired").await;
                pool.shutdown().await;
                drop((second, pool));
                peer.stop().await;
                assert_eq!(peer.closed.load(Ordering::Acquire), 2);
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }
    #[tokio::test]
    async fn trusttunnel_h3_cancelled_creation_is_joined_and_cannot_reopen_after_stop() {
        let observation = ResourceProbe::default();
        observation.scope(async {
            let pool=Pool::new(None);
            let started=Arc::new(Notify::new());
            let finished=Arc::new(AtomicBool::new(false));
            struct Released(Arc<AtomicBool>);
            impl Drop for Released {fn drop(&mut self) {self.0.store(true,Ordering::Release);}}
            let opening=pool.open_connect(request("echo.invalid:443"),Instant::now()+Duration::from_secs(30),None,{
                let started=started.clone();let finished=finished.clone();
                move||async move {
                    let _released=Released(finished);
                    started.notify_one();
                    std::future::pending::<io::Result<QuicTransport>>().await
                }
            });
                let mut opening = Box::pin(opening);
            tokio::select! { result=&mut opening=>panic!("setup completed: {}",result.is_ok()), ()=started.notified()=>{} }
            drop(opening);
                tokio::time::timeout(Duration::from_secs(2),async {
                    while !finished.load(Ordering::Acquire) { tokio::task::yield_now().await; }
                }).await.unwrap();
            pool.shutdown().await;
            assert!(finished.load(Ordering::Acquire));
            assert!(pool.tasks.is_empty());
            assert!(pool.spawn(async {}).is_err());
        }).await;
        assert!(observation.snapshot().is_idle());
    }
}
