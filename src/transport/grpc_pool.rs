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
    Connect(http::Request<()>),
}

pub struct GrpcPool {
    options: GrpcOptions,
    half_close: bool,
    connections: Arc<SyncMutex<Vec<Connection>>>,
    opening: Mutex<()>,
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
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
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
        self.open_request(RequestKind::Connect(request), deadline, connect)
            .await
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
            let (sender, lease) = {
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
                                    self.options.max_streams > 0
                                        && active < self.options.max_streams
                                }
                        })
                        .map(|connection| connection.reserve(&self.connections))
                        .transpose()?
                };
                match existing {
                    Some(pair) => pair,
                    None => {
                        let raw = connect().await?;
                        let connection = self.establish(raw).await?;
                        let pair = connection.reserve(&self.connections)?;
                        self.connections.lock().unwrap().push(connection);
                        pair
                    }
                }
            };
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
                RequestKind::Connect(request) => {
                    super::grpc::pooled_connect(sender, request, deadline, lease).await
                }
            }
        };
        tokio::select! {biased;
            ()=self.cancellation.cancelled()=>Err(io::ErrorKind::ConnectionAborted.into()),
            result=timeout_at(deadline,operation)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
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
        let observation =
            crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
        self.tasks.spawn(crate::resources::observation::bind(async move {
            let _observation=observation;
            let _lifetime=lifetime;
            if interval==0 {
                tokio::select! {biased;
                    ()=cancellation.cancelled()=>{},
                    _=&mut connection=>{},
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
            active: Arc::default(),
            token,
            _observation: crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Pool,
            ),
        })
    }
    pub fn begin_shutdown(&self) {
        self.cancellation.cancel();
    }
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.close();
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
    _observation: crate::resources::observation::Guard,
}
impl Connection {
    fn reserve(&self, pool: &Arc<SyncMutex<Vec<Connection>>>) -> io::Result<(Sender, Lease)> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        Ok((
            self.sender.clone(),
            Lease {
                active: self.active.clone(),
                closed: self.closed.clone(),
                pool: Arc::downgrade(pool),
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
}
impl Lease {
    pub(super) fn stopped(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1
            && let Some(pool) = self.pool.upgrade()
        {
            let mut idle = 0;
            pool.lock().unwrap().retain(|connection| {
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
