//! Node-owned gRPC physical connections. Policy matches Mihomo's two threshold
//! branches; bounded idle retention does not impose a business-flow quota.
use super::h2_write::{Sender, Writes};
use crate::{config::GrpcOptions, dispatch::BoxStream};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex as SyncMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
    time::{Instant, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const MAX_IDLE_CONNECTIONS: usize = crate::limits::GRPC_IDLE_CONNECTIONS;
const PING_TIMEOUT: Duration = Duration::from_secs(crate::limits::GRPC_PING_TIMEOUT_SECONDS as u64);

enum RequestKind<'a> {
    Grpc(&'a str),
    #[cfg(feature = "outbound-trusttunnel")]
    Connect(http::Request<()>, Option<Arc<dyn Fn() + Send + Sync>>),
    #[cfg(feature = "outbound-masque")]
    ConnectAdmitted(http::Request<()>),
}

pub struct GrpcPool {
    options: GrpcOptions,
    half_close: bool,
    connections: Arc<SyncMutex<Vec<Connection>>>,
    opening: Mutex<()>,
    admission: SyncMutex<()>,
    idle_timeout: Option<Duration>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
}
impl GrpcPool {
    pub fn new(options: GrpcOptions) -> Self {
        Self {
            options,
            half_close: false,
            connections: Arc::default(),
            opening: Mutex::default(),
            admission: SyncMutex::default(),
            idle_timeout: None,
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }
    #[cfg(feature = "outbound-trusttunnel")]
    pub(crate) fn connect_client() -> Self {
        let mut pool = Self::new(GrpcOptions {
            max_connections: 1,
            min_streams: 0,
            ..Default::default()
        });
        pool.idle_timeout = Some(Duration::from_secs(30));
        pool
    }
    #[cfg(feature = "outbound-masque")]
    pub(crate) fn masque_ip() -> Self {
        Self::new(GrpcOptions {
            max_connections: 1,
            min_streams: 0,
            ping_interval: 30,
            ..Default::default()
        })
    }
    /// Trojan keeps its response and lease after upload END_STREAM.
    #[cfg(any(test, feature = "outbound-trojan"))]
    pub(crate) fn duplex(options: GrpcOptions) -> Self {
        let mut pool = Self::new(options);
        pool.half_close = true;
        pool
    }
    /// The factory is invoked only for a new physical connection. A reused
    /// transport keeps its original upstream selection and TLS identity.
    pub async fn open<F, Fut>(
        &self,
        uri: &str,
        deadline: Instant,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        self.open_request(RequestKind::Grpc(uri), deadline, connect)
            .await
    }
    /// An unframed CONNECT stream shares the same physical-IO ownership and
    /// pool policy as gRPC, without importing gRPC headers or record framing.
    #[cfg(feature = "outbound-trusttunnel")]
    pub(crate) async fn open_connect<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        self.open_request(RequestKind::Connect(request, None), deadline, connect)
            .await
    }
    #[cfg(feature = "outbound-trusttunnel")]
    pub(crate) async fn open_connect_observed<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        observer: Arc<dyn Fn() + Send + Sync>,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        self.open_request(
            RequestKind::Connect(request, Some(observer)),
            deadline,
            connect,
        )
        .await
    }
    #[cfg(feature = "outbound-masque")]
    pub(crate) async fn open_connect_admitted<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        self.open_request(RequestKind::ConnectAdmitted(request), deadline, connect)
            .await
    }
    #[cfg(feature = "outbound-trusttunnel")]
    pub(crate) async fn probe<F, Fut>(
        &self,
        request: http::Request<()>,
        deadline: Instant,
        connect: F,
    ) -> io::Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        let operation = async {
            let (sender, lease) = self.acquire(connect).await?;
            super::grpc::connect_probe(sender, request, deadline, lease).await
        };
        tokio::select! {biased;
            ()=self.cancellation.cancelled()=>Err(io::ErrorKind::ConnectionAborted.into()),
            result=timeout_at(deadline,operation)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
    async fn open_request<F, Fut>(
        &self,
        request: RequestKind<'_>,
        deadline: Instant,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        let operation = async {
            // Only physical creation is serialized; waiting callers own their
            // deadline/cancellation and no detached queue or worker is created.
            let (sender, lease) = self.acquire(connect).await?;
            match request {
                RequestKind::Grpc(uri) => {
                    super::grpc::pooled_stream(
                        sender,
                        uri,
                        &self.options.user_agent,
                        self.half_close,
                        deadline,
                        lease,
                    )
                    .await
                }
                #[cfg(feature = "outbound-trusttunnel")]
                RequestKind::Connect(request, observer) => {
                    let (stream, response) =
                        super::grpc::pooled_connect(sender, request, deadline, lease, observer)
                            .await?;
                    let _admission = self.admission.lock().unwrap();
                    if self.cancellation.is_cancelled() {
                        return Err(io::ErrorKind::ConnectionAborted.into());
                    }
                    let cancellation = self.cancellation.clone();
                    self.tasks.spawn(crate::resources::observation::task(async move {
                        tokio::select! {biased; ()=cancellation.cancelled()=>{}, ()=response=>{}}
                    }));
                    Ok(stream)
                }
                #[cfg(feature = "outbound-masque")]
                RequestKind::ConnectAdmitted(request) => {
                    super::grpc::pooled_connect_admitted(sender, request, deadline, lease).await
                }
            }
        };
        tokio::select! {biased;
            ()=self.cancellation.cancelled()=>Err(io::ErrorKind::ConnectionAborted.into()),
            result=timeout_at(deadline,operation)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
    async fn acquire<F, Fut>(&self, connect: F) -> io::Result<(Sender, Lease)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        let _opening = self.opening.lock().await;
        let existing = {
            let mut connections = self.connections.lock().unwrap();
            connections.retain(|connection| !connection.closed.load(Ordering::Acquire));
            connections
                .iter()
                .min_by_key(|connection| connection.active.load(Ordering::Acquire))
                .filter(|connection| {
                    let active = connection.active.load(Ordering::Acquire);
                    active == 0
                        || if self.options.max_connections > 0 {
                            connections.len() >= self.options.max_connections
                                || active < self.options.min_streams
                        } else {
                            self.options.max_streams > 0 && active < self.options.max_streams
                        }
                })
                .map(|connection| connection.reserve(&self.connections))
                .transpose()?
        };
        match existing {
            Some(pair) => Ok(pair),
            None => {
                let raw = connect().await?;
                let connection = self.establish(raw).await?;
                let pair = connection.reserve(&self.connections)?;
                let _admission = self.admission.lock().unwrap();
                if self.cancellation.is_cancelled() {
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
                self.connections.lock().unwrap().push(connection);
                Ok(pair)
            }
        }
    }
    async fn establish(&self, raw: BoxStream) -> io::Result<Connection> {
        let last_read = Arc::new(SyncMutex::new(Instant::now()));
        let (raw, writes) = Writes::wrap(raw);
        let (sender, mut connection) = h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(super::STREAM_BUFFER_BYTES as u32)
            .initial_connection_window_size((2 * super::STREAM_BUFFER_BYTES) as u32)
            .max_frame_size(super::STREAM_CHUNK_BYTES as u32)
            .max_header_list_size(super::STREAM_CHUNK_BYTES as u32)
            .max_concurrent_streams(0)
            .max_send_buffer_size(super::STREAM_CHUNK_BYTES)
            .handshake(ActivityIo {
                raw: Box::new(raw),
                last_read: last_read.clone(),
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
        let mut ping = connection.ping_pong().expect("single PING owner");
        let closed = Arc::new(AtomicBool::new(false));
        let lifetime = Lifetime(closed.clone());
        let token = self.cancellation.child_token();
        let cancellation = token.clone();
        let interval = self.options.ping_interval;
        let active = Arc::new(AtomicUsize::new(0));
        let idle_since = Arc::new(SyncMutex::new(Some(Instant::now())));
        let activity = Arc::new(tokio::sync::Notify::new());
        let idle = idle_since.clone();
        let idle_timeout = self.idle_timeout;
        let registry = Arc::downgrade(&self.connections);
        let driver_closed = closed.clone();
        let driver_active = active.clone();
        let observation =
            crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
        let _admission = self.admission.lock().unwrap();
        if self.cancellation.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let driver_activity = activity.clone();
        self.tasks.spawn(crate::resources::observation::bind(async move {
            let _observation=observation;
            let _lifetime=lifetime;
            if interval==0 {
                loop {
                    let notified = driver_activity.notified();
                    let expires = idle_timeout.and_then(|timeout| idle.lock().unwrap().map(|since| since + timeout));
                    tokio::select! {biased;
                        ()=cancellation.cancelled()=>break,
                        _=&mut connection=>break,
                        ()=notified=>{},
                        ()=async { match expires { Some(deadline)=>tokio::time::sleep_until(deadline).await, None=>std::future::pending().await } }=>{
                            // Reserve and retire share the registry barrier.
                            // Publish retirement before a caller can reserve
                            // this connection after the idle decision.
                            let Some(registry) = registry.upgrade() else { break; };
                            let _connections = registry.lock().unwrap();
                            if driver_active.load(Ordering::Acquire)==0 && idle_timeout.zip(*idle.lock().unwrap()).is_some_and(|(timeout,since)|Instant::now()>=since+timeout) {
                                driver_closed.store(true, Ordering::Release);
                                break;
                            }
                        }
                    }
                }
                return;
            }
            loop {
                let idle_at=*last_read.lock().unwrap()+Duration::from_secs(interval);
                tokio::select! {biased;
                    ()=cancellation.cancelled()=>break,
                    _=&mut connection=>break,
                    ()=tokio::time::sleep_until(idle_at)=>{
                        if Instant::now()<*last_read.lock().unwrap()+Duration::from_secs(interval) {continue;}
                        tokio::select! {biased;
                            ()=cancellation.cancelled()=>break,
                            _=&mut connection=>break,
                            result=tokio::time::timeout(PING_TIMEOUT,ping.ping(h2::Ping::opaque()))=>{
                                if !matches!(result,Ok(Ok(_))) {break;}
                            }
                        }
                    }
                }
            }
        }));
        Ok(Connection {
            sender: Sender {
                request: sender,
                writes,
            },
            closed,
            active,
            idle_since,
            activity,
            token,
            _observation: crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Pool,
            ),
        })
    }
    pub fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancellation.cancel();
        self.tasks.close();
    }
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
        self.connections.lock().unwrap().clear();
    }
}
impl Drop for GrpcPool {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::observation::{ResourceKind, ResourceProbe};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(feature = "outbound-masque")]
    struct MasqueRequest {
        receive: h2::RecvStream,
        response: h2::server::SendResponse<bytes::Bytes>,
    }

    #[cfg(feature = "outbound-masque")]
    fn masque_request(authority: &str) -> http::Request<()> {
        http::Request::builder()
            .method("CONNECT")
            .uri(http::Uri::builder().authority(authority).build().unwrap())
            .header("cf-connect-proto", "cf-connect-ip")
            .header("pq-enabled", "false")
            .header("user-agent", "")
            .body(())
            .unwrap()
    }

    #[cfg(feature = "outbound-masque")]
    async fn masque_peer(
        peer: tokio::io::DuplexStream,
        requests: tokio::sync::mpsc::Sender<MasqueRequest>,
    ) {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        while let Some(Ok((request, response))) = connection.accept().await {
            assert_eq!(request.method(), "CONNECT");
            assert!(request.uri().scheme().is_none());
            assert!(request.extensions().get::<h2::ext::Protocol>().is_none());
            assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
            assert_eq!(request.headers()["pq-enabled"], "false");
            assert_eq!(request.headers()["user-agent"], "");
            assert!(!request.headers().contains_key("capsule-protocol"));
            if requests
                .send(MasqueRequest {
                    receive: request.into_body(),
                    response,
                })
                .await
                .is_err()
            {
                return;
            }
        }
    }

    #[cfg(feature = "outbound-masque")]
    #[tokio::test(start_paused = true)]
    async fn masque_h2_admission_preserves_data_and_sibling_until_joined_stop() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peers = TaskTracker::new();
                let pool = GrpcPool::masque_ip();
                let count = AtomicUsize::new(0);
                let (requests, mut accepted) = tokio::sync::mpsc::channel(4);
                let factory = || async {
                    count.fetch_add(1, Ordering::SeqCst);
                    let (raw, peer) = tokio::io::duplex(65536);
                    peers.spawn(masque_peer(peer, requests.clone()));
                    Ok(Box::new(raw) as BoxStream)
                };
                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("first.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let mut first_peer = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                std::future::poll_fn(|cx| {
                    assert!(opening.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let mut first_send = first_peer
                    .response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                first_send
                    .send_data(bytes::Bytes::from_static(b"server-first"), false)
                    .unwrap();
                let mut first = opening.await.unwrap();
                tokio::time::advance(Duration::from_secs(6)).await;
                let mut prefix = [0; 12];
                first.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"server-first");

                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("sibling.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let mut sibling_peer = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                let mut sibling_send = sibling_peer
                    .response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut sibling = opening.await.unwrap();

                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("reject.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let mut rejected = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                let _rejected_send = rejected
                    .response
                    .send_response(
                        http::Response::builder().status(201).body(()).unwrap(),
                        false,
                    )
                    .unwrap();
                assert_eq!(opening.await.err().unwrap().kind(), io::ErrorKind::InvalidData);
                assert!(rejected.receive.data().await.unwrap().is_err());

                first.write_all(b"past-deadline").await.unwrap();
                first.flush().await.unwrap();
                let upload = first_peer.receive.data().await.unwrap().unwrap();
                assert_eq!(upload.as_ref(), b"past-deadline");
                first_peer
                    .receive
                    .flow_control()
                    .release_capacity(upload.len())
                    .unwrap();
                first.shutdown().await.unwrap();
                assert!(first_peer.receive.data().await.unwrap().is_err());
                sibling_send
                    .send_data(bytes::Bytes::from_static(b"alive"), false)
                    .unwrap();
                let mut echo = [0; 5];
                sibling.read_exact(&mut echo).await.unwrap();
                assert_eq!(&echo, b"alive");
                assert_eq!(count.load(Ordering::SeqCst), 1);
                assert_eq!(observation.snapshot().current(ResourceKind::Task), 1);
                pool.shutdown().await;
                assert!(pool.tasks.is_empty());
                assert_eq!(observation.snapshot().current(ResourceKind::Task), 0);
                assert!(sibling.write_all(b"stopped").await.is_err());
                drop(first);
                drop(sibling);
                drop(first_send);
                drop(sibling_send);
                peers.close();
                peers.wait().await;
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }

    #[cfg(feature = "outbound-masque")]
    #[tokio::test(start_paused = true)]
    async fn masque_h2_cancel_timeout_and_stop_reset_pending_admission() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peers = TaskTracker::new();
                let pool = GrpcPool::masque_ip();
                let count = AtomicUsize::new(0);
                let (requests, mut accepted) = tokio::sync::mpsc::channel(4);
                let factory = || async {
                    count.fetch_add(1, Ordering::SeqCst);
                    let (raw, peer) = tokio::io::duplex(65536);
                    peers.spawn(masque_peer(peer, requests.clone()));
                    Ok(Box::new(raw) as BoxStream)
                };
                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("cancel.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let mut cancelled = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                drop(opening);
                assert!(cancelled.receive.data().await.unwrap().is_err());

                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("timeout.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let mut expired = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                tokio::time::advance(Duration::from_secs(6)).await;
                assert_eq!(opening.await.err().unwrap().kind(), io::ErrorKind::TimedOut);
                assert!(expired.receive.data().await.unwrap().is_err());

                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("late-ready.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let mut late = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                let _late_send = late
                    .response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                // Let the independent driver process an accepted response,
                // but do not poll admission again until setup has expired.
                tokio::time::advance(Duration::from_secs(6)).await;
                assert_eq!(opening.await.err().unwrap().kind(), io::ErrorKind::TimedOut);
                assert!(late.receive.data().await.unwrap().is_err());
                assert_eq!(count.load(Ordering::SeqCst), 1);

                let mut opening = Box::pin(pool.open_connect_admitted(
                    masque_request("stop.invalid:443"),
                    Instant::now() + Duration::from_secs(5),
                    factory,
                ));
                let _stopped = tokio::select! {
                    request=accepted.recv()=>request.unwrap(),
                    result=&mut opening=>panic!("CONNECT returned before response: {}", result.is_ok()),
                };
                pool.shutdown().await;
                assert_eq!(
                    opening.await.err().unwrap().kind(),
                    io::ErrorKind::ConnectionAborted
                );
                assert!(pool.tasks.is_empty());
                assert_eq!(observation.snapshot().current(ResourceKind::Task), 0);
                peers.close();
                peers.wait().await;
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }

    #[cfg(feature = "outbound-trusttunnel")]
    #[tokio::test]
    async fn trusttunnel_rejected_headers_wake_a_flow_control_blocked_writer() {
        let pool = GrpcPool::connect_client();
        let peers = TaskTracker::new();
        let reject = Arc::new(tokio::sync::Notify::new());
        let (accepted, ready) = tokio::sync::oneshot::channel();
        let (raw, peer) = tokio::io::duplex(65536);
        let signal = reject.clone();
        let streams = peers.clone();
        peers.spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(0)
                .handshake::<_, bytes::Bytes>(peer)
                .await
                .unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            streams.spawn(async move {
                accepted.send(()).unwrap();
                signal.notified().await;
                let send = response
                    .send_response(
                        http::Response::builder().status(403).body(()).unwrap(),
                        false,
                    )
                    .unwrap();
                let _send = send;
                let mut receive = request.into_body();
                while receive.data().await.is_some_and(|data| data.is_ok()) {}
            });
            while connection.accept().await.is_some() {}
        });
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(
                http::Uri::builder()
                    .authority("example.invalid:443")
                    .build()
                    .unwrap(),
            )
            .body(())
            .unwrap();
        let mut stream = pool
            .open_connect(request, Instant::now() + Duration::from_secs(5), || async {
                Ok(Box::new(raw) as BoxStream)
            })
            .await
            .unwrap();
        ready.await.unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        stream.write_all(b"blocked").await.unwrap();
        let (pending, reached) = tokio::sync::oneshot::channel();
        let mut pending = Some(pending);
        let writer = tokio::spawn(async move {
            let mut flush = Box::pin(stream.flush());
            std::future::poll_fn(|cx| {
                let result = flush.as_mut().poll(cx);
                if result.is_pending()
                    && let Some(signal) = pending.take()
                {
                    let _ = signal.send(());
                }
                result
            })
            .await
        });
        reached.await.unwrap();
        reject.notify_one();
        // Timeout observes the child join; its wake cannot re-poll the blocked
        // flush and hide a missing Close writer notification.
        assert!(
            tokio::time::timeout(Duration::from_secs(1), writer)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        pool.shutdown().await;
        peers.close();
        peers.wait().await;
    }

    #[cfg(feature = "outbound-trusttunnel")]
    #[tokio::test(start_paused = true)]
    async fn trusttunnel_h2_probe_idle_retirement_and_stop_admission() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let peers = TaskTracker::new();
                let count = AtomicUsize::new(0);
                let pool = GrpcPool::connect_client();
                let factory = || async {
                    count.fetch_add(1, Ordering::SeqCst);
                    let (raw, peer) = tokio::io::duplex(65536);
                    let streams = peers.clone();
                    peers.spawn(async move {
                        let mut connection = h2::server::handshake(peer).await.unwrap();
                        while let Some(Ok((request, mut response))) = connection.accept().await {
                            if request.uri().authority().unwrap().as_str() == "_check" {
                                assert!(request.body().is_end_stream());
                                response
                                    .send_response(http::Response::new(()), true)
                                    .unwrap();
                            } else {
                                let mut send = response
                                    .send_response(http::Response::new(()), false)
                                    .unwrap();
                                streams.spawn(async move {
                                    let mut receive = request.into_body();
                                    while let Some(Ok(data)) = receive.data().await {
                                        receive
                                            .flow_control()
                                            .release_capacity(data.len())
                                            .unwrap();
                                        if send.send_data(data, false).is_err() {
                                            return;
                                        }
                                    }
                                });
                            }
                        }
                    });
                    Ok(Box::new(raw) as BoxStream)
                };
                let request = |target| {
                    http::Request::builder()
                        .method("CONNECT")
                        .uri(http::Uri::builder().authority(target).build().unwrap())
                        .body(())
                        .unwrap()
                };
                let mut first = pool
                    .open_connect(
                        request("example.invalid:443"),
                        Instant::now() + Duration::from_secs(5),
                        factory,
                    )
                    .await
                    .unwrap();
                first.write_all(b"first").await.unwrap();
                first.flush().await.unwrap();
                tokio::time::advance(Duration::from_secs(6)).await;
                // Headers arrived before the read: an expired setup deadline must
                // not invalidate an established CONNECT response.
                let mut echo = [0; 5];
                first.read_exact(&mut echo).await.unwrap();
                assert_eq!(&echo, b"first");
                first.shutdown().await.unwrap();
                drop(first);
                pool.probe(
                    request("_check"),
                    Instant::now() + Duration::from_secs(7),
                    factory,
                )
                .await
                .unwrap();
                assert_eq!(count.load(Ordering::SeqCst), 1);
                tokio::time::advance(Duration::from_secs(31)).await;
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                let mut second = pool
                    .open_connect(
                        request("example.invalid:443"),
                        Instant::now() + Duration::from_secs(5),
                        factory,
                    )
                    .await
                    .unwrap();
                assert_eq!(count.load(Ordering::SeqCst), 2);
                second.write_all(b"again").await.unwrap();
                second.flush().await.unwrap();
                second.read_exact(&mut echo).await.unwrap();
                assert_eq!(&echo, b"again");
                pool.shutdown().await;
                assert!(second.write_all(b"stopped").await.is_err());
                drop(second);
                let (raw, _peer) = tokio::io::duplex(65536);
                assert!(pool.establish(Box::new(raw)).await.is_err());
                assert!(pool.tasks.is_empty());
                assert!(
                    pool.open_connect(
                        request("example.invalid:443"),
                        Instant::now() + Duration::from_secs(5),
                        factory
                    )
                    .await
                    .is_err()
                );
                assert_eq!(count.load(Ordering::SeqCst), 2);
                peers.close();
                peers.wait().await;
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }

    #[tokio::test]
    async fn grpc_duplex_pool_keeps_response_and_sibling_after_end_stream_and_joins_stop() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                tokio::time::timeout(Duration::from_secs(3), async {
                    let tasks = TaskTracker::new();
                    let count = Arc::new(AtomicUsize::new(0));
                    let pool = GrpcPool::duplex(GrpcOptions::default());
                    let factory = || async {
                        count.fetch_add(1, Ordering::SeqCst);
                        let (io, peer) = tokio::io::duplex(65536);
                        let sessions = tasks.clone();
                        tasks.spawn(async move {
                            let mut connection = h2::server::handshake(peer).await.unwrap();
                            while let Some(Ok((request, mut response))) = connection.accept().await
                            {
                                assert_eq!(request.headers()["user-agent"], "grpc-go/1.36.0");
                                let mut send = response
                                    .send_response(
                                        http::Response::builder()
                                            .status(200)
                                            .header("content-type", "application/grpc")
                                            .body(())
                                            .unwrap(),
                                        false,
                                    )
                                    .unwrap();
                                let mut receive = request.into_body();
                                sessions.spawn(async move {
                                    while let Some(data) = receive.data().await {
                                        let Ok(data) = data else {
                                            return;
                                        };
                                        receive
                                            .flow_control()
                                            .release_capacity(data.len())
                                            .unwrap();
                                        if send.send_data(data, false).is_err() {
                                            return;
                                        }
                                    }
                                    send.send_data(
                                        bytes::Bytes::from_static(b"\0\0\0\0\x06\x0a\x04tail"),
                                        false,
                                    )
                                    .unwrap();
                                    let mut trailers = http::HeaderMap::new();
                                    trailers.insert("grpc-status", "0".parse().unwrap());
                                    send.send_trailers(trailers).unwrap();
                                });
                            }
                        });
                        Ok(Box::new(io) as BoxStream)
                    };
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let mut first = pool
                        .open("http://example.com/GunService/Tun", deadline, factory)
                        .await
                        .unwrap();
                    let mut sibling = pool
                        .open("http://example.com/GunService/Tun", deadline, factory)
                        .await
                        .unwrap();
                    assert_eq!(count.load(Ordering::SeqCst), 1);
                    first.write_all(b"first").await.unwrap();
                    first.shutdown().await.unwrap();
                    first.shutdown().await.unwrap();
                    // Upload is closed, but its response and physical lease survive.
                    assert!(first.write_all(b"closed").await.is_err());
                    assert_eq!(
                        pool.connections.lock().unwrap()[0]
                            .active
                            .load(Ordering::Acquire),
                        2
                    );
                    let mut response = Vec::new();
                    first.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, b"firsttail");
                    sibling.write_all(b"alive").await.unwrap();
                    sibling.flush().await.unwrap();
                    let mut echo = [0; 5];
                    sibling.read_exact(&mut echo).await.unwrap();
                    assert_eq!(&echo, b"alive");
                    assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
                    pool.shutdown().await;
                    assert_eq!(probe.snapshot().current(ResourceKind::Task), 0);
                    assert_eq!(probe.snapshot().current(ResourceKind::Pool), 0);
                    assert!(sibling.write_all(b"stopped").await.is_err());
                    drop(first);
                    drop(sibling);
                    tasks.close();
                    tasks.wait().await;
                })
                .await
                .unwrap();
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
}
struct Connection {
    sender: Sender,
    active: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    token: CancellationToken,
    idle_since: Arc<SyncMutex<Option<Instant>>>,
    activity: Arc<tokio::sync::Notify>,
    _observation: crate::resources::observation::Guard,
}
impl Connection {
    fn reserve(&self, pool: &Arc<SyncMutex<Vec<Connection>>>) -> io::Result<(Sender, Lease)> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        *self.idle_since.lock().unwrap() = None;
        self.activity.notify_one();
        Ok((
            self.sender.clone(),
            Lease {
                active: self.active.clone(),
                closed: self.closed.clone(),
                pool: Arc::downgrade(pool),
                idle_since: self.idle_since.clone(),
                activity: self.activity.clone(),
            },
        ))
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.token.cancel();
    }
}
struct Lifetime(Arc<AtomicBool>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) struct Lease {
    active: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    pool: std::sync::Weak<SyncMutex<Vec<Connection>>>,
    idle_since: Arc<SyncMutex<Option<Instant>>>,
    activity: Arc<tokio::sync::Notify>,
}
impl Lease {
    pub(super) fn stopped(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let pool = self.pool.upgrade();
        let mut connections = pool.as_ref().map(|pool| pool.lock().unwrap());
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.idle_since.lock().unwrap() = Some(Instant::now());
            self.activity.notify_one();
            let Some(connections) = &mut connections else {
                return;
            };
            let mut idle = 0;
            connections.retain(|connection| {
                if connection.closed.load(Ordering::Acquire) {
                    return false;
                }
                if connection.active.load(Ordering::Acquire) > 0 {
                    return true;
                }
                idle += 1;
                idle <= MAX_IDLE_CONNECTIONS
            });
        }
    }
}

struct ActivityIo {
    raw: BoxStream,
    last_read: Arc<SyncMutex<Instant>>,
}
impl AsyncRead for ActivityIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.raw).poll_read(cx, buf);
        if buf.filled().len() > before {
            *self.last_read.lock().unwrap() = Instant::now();
        }
        result
    }
}
impl AsyncWrite for ActivityIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}
