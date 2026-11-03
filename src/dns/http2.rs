//! Multiplexed DoH over an authenticated, protected caller-owned stream.
//! Drivers and the idle reaper belong to one resolver's shutdown barrier.

use super::{MAX_HTTP_HEADER_BYTES, MAX_MESSAGE_SIZE};
use crate::{config::DnsNameserver, dispatch::BoxStream};
use bytes::Bytes;
use std::{
    collections::HashMap,
    hash::Hash,
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const MAX_STREAMS: usize = 32;
const MAX_IDLE: usize = 4;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct Pool<K> {
    state: Mutex<State<K>>,
    admission: Mutex<()>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    reaper_running: AtomicBool,
    max_idle: AtomicUsize,
}

struct State<K> {
    connections: Vec<(K, Arc<Connection>)>,
    initialization: HashMap<K, Weak<AsyncMutex<()>>>,
}

struct Connection {
    sender: h2::client::SendRequest<Bytes>,
    meta: Arc<Metadata>,
    streams: Arc<Semaphore>,
    driver: JoinHandle<()>,
}

struct Metadata {
    reusable: AtomicBool,
    active: AtomicUsize,
    last_used: Mutex<Instant>,
}

pub(super) struct Lease<K: Clone + Eq + Hash + Send + Sync + 'static> {
    connection: Arc<Connection>,
    owner: Weak<Pool<K>>,
}

impl<K: Clone + Eq + Hash + Send + Sync + 'static> Pool<K> {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                connections: Vec::new(),
                initialization: HashMap::new(),
            }),
            admission: Mutex::new(()),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            reaper_running: AtomicBool::new(false),
            max_idle: AtomicUsize::new(MAX_IDLE),
        })
    }

    pub(super) fn disable_idle(&self) {
        self.max_idle.store(0, Ordering::Release);
    }

    pub(super) fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub(super) fn has(&self, key: &K) -> bool {
        if self.is_closed() {
            return false;
        }
        self.state
            .lock()
            .unwrap()
            .connections
            .iter()
            .any(|(candidate, connection)| {
                candidate == key
                    && connection.meta.reusable.load(Ordering::Acquire)
                    && (connection.meta.active.load(Ordering::Acquire) != 0
                        || Instant::now()
                            .duration_since(*connection.meta.last_used.lock().unwrap())
                            < IDLE_TIMEOUT)
            })
    }

    pub(super) fn get(self: &Arc<Self>, key: &K) -> Option<Lease<K>> {
        if self.is_closed() {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        self.maintain_locked(&mut state);
        let connection = state
            .connections
            .iter()
            .find(|(candidate, connection)| {
                candidate == key && connection.meta.reusable.load(Ordering::Acquire)
            })?
            .1
            .clone();
        connection.meta.active.fetch_add(1, Ordering::AcqRel);
        Some(Lease {
            connection,
            owner: Arc::downgrade(self),
        })
    }

    /// Cold builders remain caller-owned. A canceled builder releases its
    /// per-key gate, so the next waiter can build without orphaned work.
    pub(super) fn initialization(&self, key: K) -> Arc<AsyncMutex<()>> {
        let mut state = self.state.lock().unwrap();
        state
            .initialization
            .retain(|_, gate| gate.strong_count() != 0);
        if let Some(gate) = state.initialization.get(&key).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(AsyncMutex::new(()));
        state.initialization.insert(key, Arc::downgrade(&gate));
        gate
    }

    pub(super) async fn connect(
        self: &Arc<Self>,
        key: K,
        stream: BoxStream,
        physical: impl Send + 'static,
    ) -> io::Result<Lease<K>> {
        let (sender, connection) = h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(MAX_MESSAGE_SIZE as u32)
            .initial_connection_window_size((MAX_MESSAGE_SIZE * MAX_STREAMS) as u32)
            .max_header_list_size(MAX_HTTP_HEADER_BYTES as u32)
            .max_concurrent_reset_streams(MAX_STREAMS * 2)
            .max_send_buffer_size(MAX_MESSAGE_SIZE)
            .handshake(stream)
            .await
            .map_err(error)?;
        let meta = Arc::new(Metadata {
            reusable: AtomicBool::new(true),
            active: AtomicUsize::new(1),
            last_used: Mutex::new(Instant::now()),
        });
        let finished = meta.clone();
        let driver = self.spawn(async move {
            let _physical = physical;
            let _ = connection.await;
            finished.reusable.store(false, Ordering::Release);
        })?;
        let connection = Arc::new(Connection {
            sender,
            meta,
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
            driver,
        });
        {
            // Serialize publication with shutdown, after the handshake.
            let _admission = self.admission.lock().unwrap();
            if self.is_closed() {
                return Err(closed());
            }
            self.state
                .lock()
                .unwrap()
                .connections
                .push((key, connection.clone()));
        }
        self.ensure_reaper()?;
        Ok(Lease {
            connection,
            owner: Arc::downgrade(self),
        })
    }

    fn spawn(
        &self,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> io::Result<JoinHandle<()>> {
        let _admission = self.admission.lock().unwrap();
        if self.is_closed() {
            return Err(closed());
        }
        let cancel = self.cancel.clone();
        let observation =
            crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
        Ok(self
            .tasks
            .spawn(crate::resources::observation::bind(async move {
                let _observation = observation;
                tokio::select! { biased; ()=cancel.cancelled()=>{}, ()=future=>{} }
            })))
    }

    fn maintain_locked(&self, state: &mut State<K>) {
        let now = Instant::now();
        state.connections.retain(|(_, connection)| {
            connection.meta.active.load(Ordering::Acquire) != 0
                || connection.meta.reusable.load(Ordering::Acquire)
                    && now.duration_since(*connection.meta.last_used.lock().unwrap()) < IDLE_TIMEOUT
        });
        while state
            .connections
            .iter()
            .filter(|(_, connection)| connection.meta.active.load(Ordering::Acquire) == 0)
            .count()
            > self.max_idle.load(Ordering::Acquire)
        {
            let Some(index) = state
                .connections
                .iter()
                .enumerate()
                .filter(|(_, (_, connection))| connection.meta.active.load(Ordering::Acquire) == 0)
                .min_by_key(|(_, (_, connection))| *connection.meta.last_used.lock().unwrap())
                .map(|(index, _)| index)
            else {
                break;
            };
            state.connections.swap_remove(index);
        }
    }

    fn ensure_reaper(self: &Arc<Self>) -> io::Result<()> {
        if self.reaper_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let pool = Arc::downgrade(self);
        self.spawn(async move {
            loop {
                tokio::time::sleep(IDLE_TIMEOUT).await;
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                let mut state = pool.state.lock().unwrap();
                pool.maintain_locked(&mut state);
                if state.connections.is_empty() {
                    pool.reaper_running.store(false, Ordering::Release);
                    return;
                }
            }
        })?;
        Ok(())
    }

    pub(super) fn close(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.tasks.close();
        let mut state = self.state.lock().unwrap();
        state.initialization.clear();
        let connections = std::mem::take(&mut state.connections);
        drop(state);
        drop(connections);
    }

    pub(super) async fn shutdown(&self) {
        self.close();
        self.tasks.wait().await;
    }

    #[cfg(test)]
    pub(super) fn driver_count(&self) -> usize {
        self.tasks.len()
    }
}

impl<K> Drop for Pool<K> {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.close();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

struct ResetOnDrop(h2::SendStream<Bytes>, bool);
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if !self.1 {
            self.0.send_reset(h2::Reason::CANCEL);
        }
    }
}

impl<K: Clone + Eq + Hash + Send + Sync + 'static> Lease<K> {
    pub(super) async fn exchange<R>(
        &self,
        server: &DnsNameserver,
        query: &[u8],
        validate: impl Fn(&[u8]) -> io::Result<R>,
    ) -> io::Result<(Vec<u8>, R)> {
        let result = self.exchange_inner(server, query, validate).await;
        if result.is_err() {
            self.connection
                .meta
                .reusable
                .store(false, Ordering::Release);
        }
        result
    }

    async fn exchange_inner<R>(
        &self,
        server: &DnsNameserver,
        query: &[u8],
        validate: impl Fn(&[u8]) -> io::Result<R>,
    ) -> io::Result<(Vec<u8>, R)> {
        let _permit = self
            .connection
            .streams
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| closed())?;
        let request = super::https::request(server, query)?;
        let mut sender = self
            .connection
            .sender
            .clone()
            .ready()
            .await
            .map_err(error)?;
        let (response, stream) = sender.send_request(request, true).map_err(error)?;
        let mut reset = ResetOnDrop(stream, false);
        let response = response.await.map_err(error)?;
        if response.status() != http::StatusCode::OK
            || !response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value.split(';').next().is_some_and(|value| {
                        value.trim().eq_ignore_ascii_case("application/dns-message")
                    })
                })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let expected = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .map(|value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|length| *length <= MAX_MESSAGE_SIZE)
                    .ok_or(io::ErrorKind::InvalidData)
            })
            .transpose()?;
        let mut receive = response.into_body();
        let mut body = Vec::new();
        while let Some(data) = receive.data().await {
            let data = data.map_err(error)?;
            if body.len() + data.len() > MAX_MESSAGE_SIZE {
                return Err(io::ErrorKind::InvalidData.into());
            }
            body.extend_from_slice(&data);
            receive
                .flow_control()
                .release_capacity(data.len())
                .map_err(error)?;
        }
        if expected.is_some_and(|length| body.len() != length) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(trailers) = receive.trailers().await.map_err(error)?
            && trailers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 32)
                .sum::<usize>()
                > MAX_HTTP_HEADER_BYTES
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        super::https::restore_id(query, &mut body)?;
        let validated = validate(&body)?;
        reset.1 = true;
        Ok((body, validated))
    }
}

impl<K: Clone + Eq + Hash + Send + Sync + 'static> Drop for Lease<K> {
    fn drop(&mut self) {
        // Use the same lock order as get/maintenance: pool, then timestamp.
        if let Some(owner) = self.owner.upgrade() {
            let mut state = owner.state.lock().unwrap();
            *self.connection.meta.last_used.lock().unwrap() = Instant::now();
            self.connection.meta.active.fetch_sub(1, Ordering::AcqRel);
            owner.maintain_locked(&mut state);
        } else {
            self.connection.meta.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn error(error: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error)
}
fn closed() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    struct Physical(Arc<AtomicUsize>);
    impl Drop for Physical {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[tokio::test]
    async fn doh_h2_cancel_resets_one_stream_and_stop_joins_inflight_driver() {
        let config = crate::config::Config::parse_yaml(b"mixed-port: 1080\ndns:\n  enable: true\n  nameserver: ['https://192.0.2.1/dns-query']\n").unwrap();
        let server = config.dns.nameservers[0].clone();
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let (arrived, arrival) = oneshot::channel();
        let (reset_sent, reset_seen) = oneshot::channel();
        let (third_sent, third_seen) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (_, mut first) = connection.accept().await.unwrap().unwrap();
            arrived.send(()).unwrap();
            let reason = tokio::select! {
                reason = futures_util::future::poll_fn(|cx| first.poll_reset(cx)) => reason.unwrap(),
                request = connection.accept() => panic!("unexpected request before reset: {}", request.is_some()),
            };
            assert_eq!(reason, h2::Reason::CANCEL);
            reset_sent.send(()).unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            use base64::Engine as _;
            let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(request.uri().query().unwrap().strip_prefix("dns=").unwrap())
                .unwrap();
            let query = crate::dns::classify_query(&query).unwrap();
            let wire = crate::dns::synthesize_empty_response(&query, 0).unwrap();
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/dns-message")
                .body(())
                .unwrap();
            respond
                .send_response(response, false)
                .unwrap()
                .send_data(Bytes::from(wire), true)
                .unwrap();
            let (_, _held) = connection.accept().await.unwrap().unwrap();
            third_sent.send(()).unwrap();
            // The client stops while this response remains pending.
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let pool = Pool::new();
        let physical = Arc::new(AtomicUsize::new(1));
        let first = pool
            .connect((), Box::new(client), Physical(physical.clone()))
            .await
            .unwrap();
        let query =
            crate::dns::build_query(0x2345, "first.example", crate::dns::QueryType::A).unwrap();
        let request_server = server.clone();
        let first =
            tokio::spawn(async move { first.exchange(&request_server, &query, |_| Ok(())).await });
        tokio::time::timeout(Duration::from_secs(3), arrival)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(3), reset_seen)
            .await
            .unwrap()
            .unwrap();
        let query =
            crate::dns::build_query(0x4567, "second.example", crate::dns::QueryType::A).unwrap();
        let (wire, ()) = pool
            .get(&())
            .unwrap()
            .exchange(&server, &query, |wire| {
                let classified = crate::dns::classify_query(&query).unwrap();
                crate::dns::validate_wire_response(&classified, wire)
                    .map(|_| ())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
            })
            .await
            .unwrap();
        assert_eq!(&wire[..2], &query[..2]);
        let held = pool.get(&()).unwrap();
        let third = tokio::spawn(async move { held.exchange(&server, &query, |_| Ok(())).await });
        tokio::time::timeout(Duration::from_secs(3), third_seen)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), pool.shutdown())
            .await
            .unwrap();
        assert_eq!(pool.driver_count(), 0);
        assert_eq!(physical.load(Ordering::Acquire), 0);
        assert!(pool.get(&()).is_none());
        assert!(third.await.unwrap().is_err());
        peer.await.unwrap();
    }
}
