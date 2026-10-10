//! DNS-only QUIC ownership, budgets and per-query streams over protected IO.
use super::{MAX_HTTP_HEADER_BYTES, MAX_MESSAGE_SIZE};
use crate::{
    config::DnsNameserver,
    dispatch::{DatagramBudget, DatagramTransport},
    transport::quic::{self, OwnedRuntime},
};
use bytes::{Buf, Bytes};
use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex as AsyncMutex, Semaphore, oneshot},
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const MAX_STREAMS: usize = 32;
const MAX_IDLE: usize = 4;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Doq,
    H3,
}

pub(super) struct Raw {
    pub transport: Box<dyn DatagramTransport>,
    pub peer: SocketAddr,
    pub budget: DatagramBudget,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: String,
}

enum Protocol {
    Doq(quinn::Connection),
    H3(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>),
}

struct Connection {
    protocol: Protocol,
    metadata: Arc<Metadata>,
    cancel: CancellationToken,
    streams: Arc<Semaphore>,
}
struct Metadata {
    healthy: AtomicBool,
    active: AtomicUsize,
    used: Mutex<Instant>,
}
struct State<K> {
    connections: Vec<(K, Arc<Connection>)>,
    initializing: HashMap<K, Weak<AsyncMutex<()>>>,
}

pub(super) struct Pool<K> {
    state: Mutex<State<K>>,
    admission: Mutex<()>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    reaper: AtomicBool,
    max_idle: AtomicUsize,
}
pub(super) struct Lease<K: Clone + Eq + Hash + Send + Sync + 'static> {
    connection: Arc<Connection>,
    owner: Weak<Pool<K>>,
}

/// A probe is already owned by its resolver, including its close exchange.
/// Dropping a canceled query cancels this child; Stop joins its cleanup task.
pub(super) struct Pending<K: Clone + Eq + Hash + Send + Sync + 'static> {
    owner: Arc<Pool<K>>,
    key: Option<K>,
    ready: oneshot::Receiver<io::Result<Protocol>>,
    done: Option<oneshot::Receiver<()>>,
    protocol: Option<Protocol>,
    metadata: Arc<Metadata>,
    cancel: CancellationToken,
    published: bool,
}

impl<K: Clone + Eq + Hash + Send + Sync + 'static> Pool<K> {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                connections: Vec::new(),
                initializing: HashMap::new(),
            }),
            admission: Mutex::new(()),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            reaper: AtomicBool::new(false),
            max_idle: AtomicUsize::new(MAX_IDLE),
        })
    }
    pub(super) fn disable_idle(&self) {
        self.max_idle.store(0, Ordering::Release);
    }
    pub(super) fn has(&self, key: &K) -> bool {
        !self.cancel.is_cancelled()
            && self
                .state
                .lock()
                .unwrap()
                .connections
                .iter()
                .any(|(candidate, connection)| candidate == key && live(connection))
    }
    pub(super) fn get(self: &Arc<Self>, key: &K) -> Option<Lease<K>> {
        if self.cancel.is_cancelled() {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        self.maintain(&mut state);
        let connection = state
            .connections
            .iter()
            .find(|(candidate, connection)| candidate == key && live(connection))?
            .1
            .clone();
        connection.metadata.active.fetch_add(1, Ordering::AcqRel);
        Some(Lease {
            connection,
            owner: Arc::downgrade(self),
        })
    }
    pub(super) fn initialization(&self, key: K) -> Arc<AsyncMutex<()>> {
        let mut state = self.state.lock().unwrap();
        state
            .initializing
            .retain(|_, gate| gate.strong_count() != 0);
        if let Some(gate) = state.initializing.get(&key).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(AsyncMutex::new(()));
        state.initializing.insert(key, Arc::downgrade(&gate));
        gate
    }
    pub(super) fn start(
        self: &Arc<Self>,
        key: K,
        kind: Kind,
        open: impl Future<Output = io::Result<Raw>> + Send + 'static,
    ) -> io::Result<Pending<K>> {
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        let cancel = self.cancel.child_token();
        let metadata = Arc::new(Metadata {
            healthy: AtomicBool::new(true),
            active: AtomicUsize::new(0),
            used: Mutex::new(Instant::now()),
        });
        let (ready, response) = oneshot::channel();
        let (done, completed) = oneshot::channel();
        let observation =
            crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
        let stop = cancel.clone();
        let meta = metadata.clone();
        self.tasks
            .spawn(crate::resources::observation::bind(async move {
                let _observation = observation;
                drive(open, kind, stop, meta, ready).await;
                let _ = done.send(());
            }));
        Ok(Pending {
            owner: self.clone(),
            key: Some(key),
            ready: response,
            done: Some(completed),
            protocol: None,
            metadata,
            cancel,
            published: false,
        })
    }
    fn maintain(&self, state: &mut State<K>) {
        state.connections.retain(|(_, connection)| {
            connection.metadata.active.load(Ordering::Acquire) != 0 || live(connection)
        });
        while state
            .connections
            .iter()
            .filter(|(_, connection)| connection.metadata.active.load(Ordering::Acquire) == 0)
            .count()
            > self.max_idle.load(Ordering::Acquire)
        {
            let Some(index) = state
                .connections
                .iter()
                .enumerate()
                .filter(|(_, (_, connection))| {
                    connection.metadata.active.load(Ordering::Acquire) == 0
                })
                .min_by_key(|(_, (_, connection))| *connection.metadata.used.lock().unwrap())
                .map(|(index, _)| index)
            else {
                break;
            };
            state.connections.swap_remove(index);
        }
    }
    fn start_reaper(self: &Arc<Self>) {
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() || self.reaper.swap(true, Ordering::AcqRel) {
            return;
        }
        let owner = Arc::downgrade(self);
        let cancel = self.cancel.clone();
        self.tasks.spawn(crate::resources::observation::task(async move {
            loop {
                tokio::select! { biased; ()=cancel.cancelled()=>return, ()=tokio::time::sleep(IDLE_TIMEOUT)=>{} }
                let Some(owner) = owner.upgrade() else { return; };
                let mut state = owner.state.lock().unwrap();
                owner.maintain(&mut state);
                if state.connections.is_empty() { owner.reaper.store(false, Ordering::Release); return; }
            }
        }));
    }
    pub(super) fn close(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.tasks.close();
        let mut state = self.state.lock().unwrap();
        state.initializing.clear();
        let connections = std::mem::take(&mut state.connections);
        drop(state);
        drop(connections);
    }
    pub(super) async fn shutdown(&self) {
        self.close();
        self.tasks.wait().await;
    }
    #[cfg(test)]
    pub(super) fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

fn live(connection: &Connection) -> bool {
    connection.metadata.healthy.load(Ordering::Acquire)
        && !connection.cancel.is_cancelled()
        && (connection.metadata.active.load(Ordering::Acquire) != 0
            || Instant::now().duration_since(*connection.metadata.used.lock().unwrap())
                < IDLE_TIMEOUT)
}
impl<K> Drop for Pool<K> {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.close();
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl<K: Clone + Eq + Hash + Send + Sync + 'static> Pending<K> {
    pub(super) async fn wait_ready(&mut self) -> io::Result<()> {
        self.protocol = Some((&mut self.ready).await.map_err(|_| closed())??);
        Ok(())
    }
    pub(super) fn publish(mut self) -> io::Result<Lease<K>> {
        let connection = Arc::new(Connection {
            protocol: self.protocol.take().ok_or_else(closed)?,
            metadata: self.metadata.clone(),
            cancel: self.cancel.clone(),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
        });
        {
            let _admission = self.owner.admission.lock().unwrap();
            if self.owner.cancel.is_cancelled()
                || !connection.metadata.healthy.load(Ordering::Acquire)
            {
                return Err(closed());
            }
            connection.metadata.active.store(1, Ordering::Release);
            self.owner
                .state
                .lock()
                .unwrap()
                .connections
                .push((self.key.take().unwrap(), connection.clone()));
        }
        self.published = true;
        self.owner.start_reaper();
        Ok(Lease {
            connection,
            owner: Arc::downgrade(&self.owner),
        })
    }
    pub(super) async fn finish(mut self) -> io::Result<Lease<K>> {
        self.wait_ready().await?;
        self.publish()
    }
    pub(super) async fn cancel(mut self) {
        self.cancel.cancel();
        if let Some(done) = self.done.take() {
            let _ = done.await;
        }
    }
}
impl<K: Clone + Eq + Hash + Send + Sync + 'static> Drop for Pending<K> {
    fn drop(&mut self) {
        if !self.published {
            self.cancel.cancel();
        }
    }
}

async fn drive(
    open: impl Future<Output = io::Result<Raw>>,
    kind: Kind,
    stop: CancellationToken,
    metadata: Arc<Metadata>,
    ready: oneshot::Sender<io::Result<Protocol>>,
) {
    let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
    let mut endpoint = None;
    let mut datagram = None;
    let mut ready = Some(ready);
    let connected = async {
        let raw = open.await?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(raw.tls).map_err(failure)?;
        let (socket, driver) = quic::attach(raw.transport, raw.peer, raw.budget)?;
        datagram = Some(driver);
        let mtu = socket.budget().quic_payload_limit()?;
        let mut limits = quinn::TransportConfig::default();
        limits
            .initial_mtu(mtu)
            .min_mtu(mtu)
            .mtu_discovery_config(None)
            .max_concurrent_bidi_streams(0_u8.into())
            .max_concurrent_uni_streams((if matches!(kind, Kind::H3) { 4_u8 } else { 0 }).into())
            .stream_receive_window(((MAX_MESSAGE_SIZE + 2) as u32).into())
            .receive_window(((MAX_MESSAGE_SIZE * MAX_STREAMS) as u32).into())
            .send_window((MAX_MESSAGE_SIZE * MAX_STREAMS) as u64)
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0)
            .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().map_err(failure)?));
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(Arc::new(limits));
        let mut config = quinn::EndpointConfig::default();
        config.max_udp_payload_size(mtu).map_err(failure)?;
        let mut peer =
            quinn::Endpoint::new_with_abstract_socket(config, None, socket, runtime.clone())?;
        peer.set_default_client_config(client);
        endpoint = Some(peer);
        let connection = endpoint
            .as_ref()
            .unwrap()
            .connect(raw.peer, &raw.server_name)
            .map_err(failure)?
            .await
            .map_err(failure)?;
        let handshake = connection
            .handshake_data()
            .ok_or_else(closed)?
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .map_err(|_| closed())?;
        let alpn: &[u8] = if matches!(kind, Kind::Doq) {
            b"doq"
        } else {
            b"h3"
        };
        if handshake.protocol.as_deref() != Some(alpn) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match kind {
            Kind::Doq => {
                ready
                    .take()
                    .unwrap()
                    .send(Ok(Protocol::Doq(connection.clone())))
                    .map_err(|_| closed())?;
                connection.closed().await;
            }
            Kind::H3 => {
                let (mut control, requests) = h3::client::builder()
                    .max_field_section_size(MAX_HTTP_HEADER_BYTES as u64)
                    .build(h3_quinn::Connection::new(connection))
                    .await
                    .map_err(failure)?;
                let keep_requests = requests.clone();
                ready
                    .take()
                    .unwrap()
                    .send(Ok(Protocol::H3(requests)))
                    .map_err(|_| closed())?;
                let _ = control.wait_idle().await;
                drop(keep_requests);
            }
        }
        Ok::<_, io::Error>(())
    };
    let result =
        tokio::select! { biased; ()=stop.cancelled()=>Err(closed()), result=connected=>result };
    metadata.healthy.store(false, Ordering::Release);
    if let Some(ready) = ready {
        let _ = ready.send(Err(result.err().unwrap_or_else(closed)));
    }
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u8.into(), b"");
        let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, endpoint.wait_idle()).await;
    }
    runtime.stop().await;
    if let Some(driver) = datagram {
        let _ = driver.stop().await;
    }
}

struct DoqStream {
    send: quinn::SendStream,
    receive: quinn::RecvStream,
    completed: bool,
}
impl Drop for DoqStream {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.send.reset(3_u8.into());
            let _ = self.receive.stop(3_u8.into());
        }
    }
}
struct H3Stream(
    h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    bool,
);
impl Drop for H3Stream {
    fn drop(&mut self) {
        if !self.1 {
            self.0.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            self.0.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
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
                .metadata
                .healthy
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
        if query.len() < 12 || query.len() > MAX_MESSAGE_SIZE {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let _permit = self
            .connection
            .streams
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| closed())?;
        match &self.connection.protocol {
            Protocol::Doq(connection) => {
                let (send, receive) = connection.open_bi().await.map_err(failure)?;
                let mut stream = DoqStream {
                    send,
                    receive,
                    completed: false,
                };
                let mut wire = Vec::with_capacity(query.len() + 2);
                wire.extend_from_slice(&(query.len() as u16).to_be_bytes());
                wire.extend_from_slice(query);
                wire[2..4].fill(0);
                stream.send.write_all(&wire).await.map_err(failure)?;
                stream.send.finish().map_err(failure)?;
                let length = stream.receive.read_u16().await? as usize;
                if !(12..=MAX_MESSAGE_SIZE).contains(&length) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut response = vec![0; length];
                stream
                    .receive
                    .read_exact(&mut response)
                    .await
                    .map_err(failure)?;
                if stream
                    .receive
                    .read(&mut [0; 1])
                    .await
                    .map_err(failure)?
                    .is_some()
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                super::https::restore_id(query, &mut response)?;
                let validated = validate(&response)?;
                stream.completed = true;
                Ok((response, validated))
            }
            Protocol::H3(sender) => {
                let mut sender = sender.clone();
                let mut stream = H3Stream(
                    sender
                        .send_request(super::https::request(server, query)?)
                        .await
                        .map_err(failure)?,
                    false,
                );
                stream.0.finish().await.map_err(failure)?;
                let headers = stream.0.recv_response().await.map_err(failure)?;
                let length = super::https::validate_headers(headers.status(), headers.headers())?;
                let mut response = Vec::new();
                while let Some(mut bytes) = stream.0.recv_data().await.map_err(failure)? {
                    if response.len() + bytes.remaining() > MAX_MESSAGE_SIZE {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    response.extend_from_slice(&bytes.copy_to_bytes(bytes.remaining()));
                }
                if length.is_some_and(|length| length != response.len()) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let _ = stream.0.recv_trailers().await.map_err(failure)?;
                super::https::restore_id(query, &mut response)?;
                let validated = validate(&response)?;
                stream.1 = true;
                Ok((response, validated))
            }
        }
    }
}
impl<K: Clone + Eq + Hash + Send + Sync + 'static> Drop for Lease<K> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            let mut state = owner.state.lock().unwrap();
            *self.connection.metadata.used.lock().unwrap() = Instant::now();
            self.connection
                .metadata
                .active
                .fetch_sub(1, Ordering::AcqRel);
            owner.maintain(&mut state);
        } else {
            self.connection
                .metadata
                .active
                .fetch_sub(1, Ordering::AcqRel);
        }
    }
}
fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("DNS QUIC exchange failed")
}
fn closed() -> io::Error {
    io::ErrorKind::ConnectionAborted.into()
}
