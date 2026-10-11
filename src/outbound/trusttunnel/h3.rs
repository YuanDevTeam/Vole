//! One logical TrustTunnel client's physical HTTP/3 session. Creation and
//! request streams use supplied datagrams; the pool owns every protocol task.
use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport},
    resources::observation::{self, ResourceKind},
    transport::{h3_stream, quic},
};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::{
    future::Future,
    io,
    net::SocketAddr,
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
const STREAM_WINDOW: u32 = 128 * 1024;
const CONNECTION_WINDOW: u32 = 256 * 1024;
const SEND_WINDOW: u64 = 64 * 1024;
const CHUNK: usize = crate::transport::STREAM_CHUNK_BYTES;
type Sender = h3::client::SendRequest<h3_stream::OpenStreams, Bytes>;
type SendStream = h3::client::RequestStream<h3_stream::SendStream, Bytes>;
type RecvStream = h3::client::RequestStream<h3_stream::RecvStream, Bytes>;
type SendOperation = Pin<Box<dyn Future<Output = (SendHalf, io::Result<()>)> + Send + 'static>>;
type Observer = Arc<dyn Fn() + Send + Sync>;

pub(super) struct QuicTransport {
    pub transport: Box<dyn DatagramTransport>,
    pub peer: SocketAddr,
    pub budget: DatagramBudget,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: String,
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
    connection: Mutex<Option<quinn::Connection>>,
    activity: Notify,
    cancel: CancellationToken,
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
            && (usage.retiring || usage.idle_since.is_some_and(|since| now >= since + IDLE))
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

pub(super) struct Pool {
    connection: Arc<Mutex<Option<Entry>>>,
    opening: tokio::sync::Mutex<()>,
    admission: Mutex<()>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    congestion: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
}
impl Pool {
    pub fn new(
        congestion: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
    ) -> Self {
        Self {
            connection: Arc::default(),
            opening: tokio::sync::Mutex::new(()),
            admission: Mutex::new(()),
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
            congestion,
        }
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
        let operation = async {
            let _waiter = observation::track(ResourceKind::Waiter);
            let (mut sender, lease) = self.acquire(deadline, connect).await?;
            let request = sender.send_request(request).await.map_err(|error| {
                retire_on_connection_error(&lease, &error);
                closed()
            })?;
            let (send, receive) = request.split();
            let close = Arc::new(Close::default());
            let (ready, response) = oneshot::channel();
            let cancellation = self.cancellation.clone();
            let headers_close = close.clone();
            let headers_physical = lease.0.clone();
            self.spawn(async move {
                let mut receive = ReceiveHalf(receive);
                let result = tokio::select! {biased;
                    ()=cancellation.cancelled()=>Err(closed()),
                    ()=headers_close.cancel.cancelled()=>Err(closed()),
                    ()=headers_physical.cancel.cancelled()=>Err(closed()),
                    response=receive.0.recv_response()=>response
                        .map_err(|error| { retire_physical(&headers_physical, &error); closed() })
                        .and_then(|response|if response.status()==200 {Ok(())} else {Err(closed())}),
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
            Ok(Box::new(Stream {
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
            }) as BoxStream)
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
        });
        let (ready, response) = oneshot::channel();
        let congestion = self.congestion.clone();
        let registry = Arc::downgrade(&self.connection);
        self.spawn(drive(
            connect,
            deadline,
            physical.clone(),
            registry,
            congestion,
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
    congestion: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
    ready: oneshot::Sender<io::Result<Entry>>,
) where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<QuicTransport>> + Send + 'static,
{
    let runtime = Arc::new(quic::OwnedRuntime::new(CancellationToken::new()));
    let mut endpoint = None;
    let mut datagram = None;
    let mut ready = Some(ready);
    let mut control = None;
    let mut keep_sender = None;
    let mut pool_observation = None;
    let establishment = async {
        let _handshake = observation::track(ResourceKind::Handshake);
        let raw = connect().await?;
        let (socket, driver) = quic::attach(raw.transport, raw.peer, raw.budget)?;
        datagram = Some(driver);
        let mtu = socket.budget().quic_payload_limit()?;
        let mut transport = quinn::TransportConfig::default();
        let discovery = if cfg!(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "android",
            target_os = "macos"
        )) {
            let mut discovery = quinn::MtuDiscoveryConfig::default();
            discovery.upper_bound(mtu);
            Some(discovery)
        } else {
            None
        };
        transport
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(discovery)
            .max_concurrent_bidi_streams(0_u8.into())
            .max_concurrent_uni_streams(8_u8.into())
            .stream_receive_window(STREAM_WINDOW.into())
            .receive_window(CONNECTION_WINDOW.into())
            .send_window(SEND_WINDOW)
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0)
            .max_idle_timeout(Some(QUIC_IDLE.try_into().map_err(|_| closed())?));
        if let Some(congestion) = congestion {
            transport.congestion_controller_factory(congestion);
        }
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(raw.tls).map_err(|_| closed())?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(Arc::new(transport));
        client.version(1);
        let mut limits = quinn::EndpointConfig::default();
        limits.max_udp_payload_size(mtu).map_err(|_| closed())?;
        let mut ep =
            quinn::Endpoint::new_with_abstract_socket(limits, None, socket, runtime.clone())?;
        ep.set_default_client_config(client);
        endpoint = Some(ep);
        let connected = endpoint
            .as_ref()
            .unwrap()
            .connect(raw.peer, &raw.server_name)
            .map_err(|_| closed())?
            .await
            .map_err(|_| closed())?;
        let negotiated = connected
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol);
        if negotiated.as_deref() != Some(b"h3") {
            return Err(closed());
        }
        *physical.connection.lock().unwrap() = Some(connected.clone());
        let (driver, sender) = h3::client::builder()
            .max_field_section_size(CHUNK as u64)
            .build(h3_stream::Connection::new(connected))
            .await
            .map_err(|_| closed())?;
        control = Some(driver);
        keep_sender = Some(sender.clone());
        pool_observation = Some(observation::track(ResourceKind::Pool));
        ready
            .take()
            .unwrap()
            .send(Ok(Entry {
                sender,
                physical: physical.clone(),
                draining: false,
            }))
            .map_err(|_| closed())?;
        Ok::<_, io::Error>(())
    };
    let setup = tokio::select! {biased;
        ()=physical.cancel.cancelled()=>Err(closed()),
        result=timeout_at(deadline,establishment)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut)).and_then(|result|result),
    };
    if let Err(error) = setup {
        if let Some(ready) = ready.take() {
            let _ = ready.send(Err(error));
        }
    } else {
        let control = control.as_mut().unwrap();
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
                .map(|since| since + IDLE);
            tokio::select! {biased;
                ()=physical.cancel.cancelled()=>break,
                _=control.wait_idle()=>break,
                ()=activity=>{},
                ()=async{ match expires { Some(deadline)=>tokio::time::sleep_until(deadline).await, None=>std::future::pending().await } }=>{
                    if physical.retire_idle(Instant::now()) { break; }
                }
            }
        }
    }
    physical.usage.lock().unwrap().closed = true;
    physical.cancel.cancel();
    // Logical cancellation must not cancel Quinn's runtime until the bounded
    // CONNECTION_CLOSE exchange has had its chance to reach the supplied IO.
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u8.into(), b"");
        let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, endpoint.wait_idle()).await;
    }
    drop(control);
    drop(keep_sender);
    physical.connection.lock().unwrap().take();
    runtime.stop().await;
    if let Some(driver) = datagram {
        let _ = driver.stop().await;
    }
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

fn retire_on_connection_error(lease: &Lease, error: &h3::error::StreamError) {
    retire_physical(&lease.0, error);
}
fn retire_physical(physical: &Physical, _: &h3::error::StreamError) {
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
        self.stream
            .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}
struct ReceiveHalf(RecvStream);
impl Drop for ReceiveHalf {
    fn drop(&mut self) {
        self.0.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
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
        dispatch::DispatchError,
        resources::observation::ResourceProbe,
        session::{Datagram, Destination},
    };
    use async_trait::async_trait;
    use std::{io::IoSliceMut, sync::atomic::AtomicUsize};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
    };

    struct Packets {
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
            Ok(Datagram {
                remote: Destination::Ip(self.peer),
                payload: self.receive.recv().await.ok_or(DispatchError::NotAllowed)?,
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
    struct Peer {
        client: Arc<rustls::ClientConfig>,
        server: rustls::ServerConfig,
        cancel: CancellationToken,
        tasks: TaskTracker,
        calls: AtomicUsize,
        closed: Arc<AtomicUsize>,
        checks: AtomicUsize,
        reject: Arc<Notify>,
        goaway: Notify,
    }
    impl Peer {
        fn new() -> Arc<Self> {
            let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(identity.cert.der().clone()).unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client.alpn_protocols = vec![b"h3".to_vec()];
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
                client: Arc::new(client),
                server,
                cancel: CancellationToken::new(),
                tasks: TaskTracker::new(),
                calls: AtomicUsize::new(0),
                closed: Arc::new(AtomicUsize::new(0)),
                checks: AtomicUsize::new(0),
                reject: Arc::new(Notify::new()),
                goaway: Notify::new(),
            })
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
                        assert_eq!(request.headers()["proxy-authorization"],"Basic dTpw");
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
                                    handler.reject.notified().await;
                                    stream.send_response(http::Response::builder().status(407).body(()).unwrap()).await.unwrap();
                                    stream.finish().await.unwrap();
                                } else {
                                    let first=stream.recv_data().await.unwrap().unwrap();
                                    let mut first=first;
                                    let first=first.copy_to_bytes(first.remaining());
                                    stream.send_response(http::Response::new(())).await.unwrap();
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
                    send: to_server,
                    receive: from_server,
                    peer: local,
                    closed: self.closed.clone(),
                }),
                peer: local,
                budget: DatagramBudget::new(1400, 1400),
                tls: self.client.clone(),
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
        super::super::authority_request(target, "Basic dTpw", "memory").unwrap()
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
    #[tokio::test]
    async fn trusttunnel_h3_deferred_headers_share_streams_probe_and_join_stop() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peer = Peer::new();
                let pool = Pool::new(quic::congestion_controller("bbr", 0, "standard"));
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
