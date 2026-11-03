//! Carrier ownership, idle reuse and serialized AEAD framing.
//! LOW pools separate business types; TCP pooling isolates concurrent slow readers.
use super::{
    crypto,
    pattern::{EffectivePattern, HostProfile, NonceState},
    stream::{RawStream, State, closed},
    wire::{
        DataKind, DataMetadata, Metadata, SessionKind, SessionMetadata, StreamDecoder,
        StreamEncoder,
    },
};
use crate::{
    config::{MieruMultiplexing, MieruOutboundConfig, MieruTransport},
    dispatch::BoxStream,
    outbound::{EstablishContext, UpstreamPath, server_destination},
    resources::observation::{self, ResourceKind},
    session::StreamSession,
};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const CLEAN_INTERVAL: Duration = Duration::from_secs(5);
const WRITER_COMMANDS: usize = 2;

#[cfg(test)]
#[path = "tcp_receive_memory_tests.rs"]
mod receive_memory_tests;
#[cfg(test)]
#[path = "udp_admission_memory_tests.rs"]
mod udp_admission_memory_tests;
#[cfg(test)]
#[path = "udp_pool_memory_tests.rs"]
mod udp_pool_memory_tests;
#[cfg(test)]
#[path = "udp_send_credit_memory_tests.rs"]
mod udp_send_credit_memory_tests;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Business {
    TcpConnect,
    UdpAssociate,
}
impl Business {
    pub fn command(self) -> u8 {
        match self {
            Self::TcpConnect => crate::socks5::COMMAND_CONNECT,
            Self::UdpAssociate => crate::socks5::COMMAND_UDP_ASSOCIATE,
        }
    }
}
pub(super) struct WriterCommand {
    pub state: Arc<State>,
    pub data: Bytes,
    pub piggyback: bool,
    pub done: oneshot::Sender<io::Result<()>>,
    pub _bytes: OwnedSemaphorePermit,
}
pub(super) struct Schedule {
    pending: usize,
    last_schedule: Instant,
    disabled: Option<Instant>,
    closed: bool,
    in_bytes: u64,
    out_bytes: u64,
}
pub(super) struct Shared {
    pub(super) sessions: Mutex<HashMap<u32, Arc<State>>>,
    control: mpsc::Sender<Metadata>,
    pub(super) schedule: Mutex<Schedule>,
    pub(super) cancel: CancellationToken,
    pub(super) activity: Arc<Notify>,
    idle: Duration,
    pub(super) volume: u64,
    created: Instant,
    udp: bool,
    // LOW separates business types on either carrier; other modes share a pool.
    business: Option<Business>,
    maximum_write: AtomicUsize,
}
impl Shared {
    #[cfg(test)]
    pub(super) fn output_test_shared(cancel: CancellationToken) -> Arc<Self> {
        let (control, _receiver) = mpsc::channel(1);
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            control,
            schedule: Mutex::new(Schedule {
                pending: 0,
                last_schedule: Instant::now(),
                disabled: None,
                closed: false,
                in_bytes: 0,
                out_bytes: 0,
            }),
            cancel,
            activity: Arc::new(Notify::new()),
            idle: Duration::from_secs(120),
            volume: u64::MAX,
            created: Instant::now(),
            udp: true,
            business: None,
            maximum_write: AtomicUsize::new(32768),
        })
    }

    pub(super) fn reap_unopened(&self) {
        self.sessions.lock().unwrap().retain(|_, state| {
            !(state.cancel.is_cancelled() && !state.opened.load(Ordering::Acquire))
        });
    }

    pub(super) fn set_maximum_write(&self, value: usize) {
        self.maximum_write.store(value, Ordering::Release);
    }
    pub(super) fn count_input(&self, count: usize) {
        self.schedule.lock().unwrap().in_bytes += count as u64;
    }
    pub(super) fn count_output(&self, count: usize) {
        self.schedule.lock().unwrap().out_bytes += count as u64;
    }

    fn reserve(&self, idle_only: bool) -> bool {
        let active = idle_only && self.count() != 0;
        let mut schedule = self.schedule.lock().unwrap();
        if schedule.closed
            || schedule.disabled.is_some()
            || self.cancel.is_cancelled()
            || active
            || (idle_only && schedule.pending != 0)
        {
            return false;
        }
        schedule.pending += 1;
        schedule.last_schedule = Instant::now();
        true
    }
    fn release(&self) {
        let mut schedule = self.schedule.lock().unwrap();
        schedule.pending -= 1;
        schedule.last_schedule = Instant::now();
    }
    fn count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|state| {
                !state.local_closed.load(Ordering::Acquire)
                    && !state.remote_closed.load(Ordering::Acquire)
            })
            .count()
    }
    pub(super) fn clean(&self) -> bool {
        let active = self.count();
        let mut schedule = self.schedule.lock().unwrap();
        let now = Instant::now();
        if self.udp && now >= self.created + Duration::from_secs(60) && schedule.disabled.is_none()
        {
            schedule.disabled = Some(now);
        }
        if active == 0
            && schedule.pending == 0
            && now >= schedule.last_schedule + self.idle
            && schedule.disabled.is_none()
        {
            schedule.disabled = Some(now);
        }
        if (schedule.in_bytes > self.volume || schedule.out_bytes > self.volume)
            && schedule.disabled.is_none()
        {
            schedule.disabled = Some(now);
        }
        if active == 0
            && schedule.pending == 0
            && schedule.disabled.is_some_and(|disabled| {
                now >= disabled + self.idle && now >= schedule.last_schedule + self.idle
            })
        {
            schedule.closed = true;
            return true;
        }
        false
    }
    pub(super) fn fail(&self) {
        self.cancel.cancel();
        self.schedule.lock().unwrap().closed = true;
        for state in self.sessions.lock().unwrap().values() {
            state.finish(true);
        }
        self.activity.notify_one();
    }
}
// The scheduler counts carrier traffic, including authenticated headers and padding.
struct CountedIo {
    io: BoxStream,
    shared: Arc<Shared>,
}
impl AsyncRead for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        self.shared.schedule.lock().unwrap().in_bytes += (buf.filled().len() - before) as u64;
        result
    }
}
impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.shared.schedule.lock().unwrap().out_bytes += *count as u64;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
pub(super) struct Carrier {
    shared: Arc<Shared>,
    pub writer: mpsc::Sender<WriterCommand>,
    pub bytes: Arc<Semaphore>,
}
impl Carrier {
    pub fn maximum_write(&self) -> usize {
        self.shared.maximum_write.load(Ordering::Acquire)
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}
struct Reservation(Arc<Carrier>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.shared.release();
    }
}
struct Factory {
    config: MieruOutboundConfig,
    upstream: UpstreamPath,
    pattern: Arc<EffectivePattern>,
}
#[derive(Default)]
struct Registry {
    next: u64,
    carriers: HashMap<u64, Arc<Carrier>>,
}
pub(super) struct Client {
    factory: Arc<Factory>,
    registry: Arc<Mutex<Registry>>,
    admission: Mutex<()>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    capacity: usize,
    factor: usize,
    idle: Duration,
}
impl Client {
    pub fn new(
        config: &MieruOutboundConfig,
        upstream: UpstreamPath,
        capacity: usize,
    ) -> io::Result<Self> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Mieru stream buffer capacity",
            ));
        }
        let factor = match config.multiplexing {
            MieruMultiplexing::Off => 0,
            MieruMultiplexing::Low => 1,
            MieruMultiplexing::Middle => 2,
            MieruMultiplexing::High => 3,
        };
        let host = HostProfile::capture();
        let idle = Duration::from_secs(120 + u64::from(host.fixed_int(61)));
        let pattern = Arc::new(EffectivePattern::compile(
            config.traffic_pattern.as_deref(),
            host,
            &config.username,
        )?);
        Ok(Self {
            factory: Arc::new(Factory {
                config: config.clone(),
                upstream,
                pattern,
            }),
            registry: Arc::default(),
            admission: Mutex::new(()),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            capacity,
            factor,
            idle,
        })
    }
    pub(super) fn queues_datagrams(&self) -> bool {
        self.factory.config.transport == MieruTransport::Udp
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub fn spawn(&self, future: BoxFuture<'static, ()>) -> io::Result<JoinHandle<()>> {
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        Ok(self.tasks.spawn(observation::task(future)))
    }
    fn reserve_reusable(
        &self,
        business: Business,
        choose: impl FnOnce(usize) -> usize,
    ) -> io::Result<Option<Reservation>> {
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        let pool = self.pool(business);
        // Isolate slow TCP readers without dedicating a carrier to every UDP target.
        // Reservations cover the gap before open publishes its session.
        let idle_only = self.factory.config.transport == MieruTransport::Tcp
            && pool == Some(Business::TcpConnect);
        let registry = self.registry.lock().unwrap();
        let available: Vec<_> = registry
            .carriers
            .values()
            .filter(|carrier| {
                carrier.shared.clean();
                let active = idle_only && carrier.shared.count() != 0;
                let schedule = carrier.shared.schedule.lock().unwrap();
                carrier.shared.business == pool
                    && !schedule.closed
                    && schedule.disabled.is_none()
                    && !active
                    && (!idle_only || schedule.pending == 0)
            })
            .cloned()
            .collect();
        let weight = available
            .len()
            .checked_mul(self.factor)
            .ok_or_else(closed)?;
        let choice = choose(weight);
        Ok(if choice < weight {
            let start = choice / self.factor;
            let mut selected = start;
            if self.factor == 1 && self.factory.config.transport == MieruTransport::Udp {
                // A setup-time estimate only; release the session lock before
                // reading pending reservations, without a second ownership ledger.
                let load = |carrier: &Arc<Carrier>| {
                    let active = carrier.shared.count();
                    let pending = carrier.shared.schedule.lock().unwrap().pending;
                    active.saturating_add(pending)
                };
                let mut selected_load = load(&available[start]);
                for offset in 1..available.len() {
                    let index = (start + offset) % available.len();
                    let candidate_load = load(&available[index]);
                    if candidate_load < selected_load {
                        selected = index;
                        selected_load = candidate_load;
                    }
                }
            }
            let carrier = available[selected].clone();
            if carrier.shared.reserve(idle_only) {
                Some(Reservation(carrier))
            } else {
                None
            }
        } else {
            None
        })
    }
    fn pool(&self, business: Business) -> Option<Business> {
        (self.factor == 1).then_some(business)
    }
    pub async fn open(
        &self,
        session: StreamSession,
        business: Business,
        datagram_receive_budget: Option<u16>,
        context: &EstablishContext,
    ) -> io::Result<RawStream> {
        // TCP UDP-associate readers need one bounded packet envelope, not a
        // full TCP stream window per destination. Physical UDP retains its
        // existing capacity for reliable windows and reordered data.
        let receive_capacity = if business == Business::UdpAssociate
            && self.factory.config.transport == MieruTransport::Tcp
        {
            datagram_receive_budget.map_or(self.capacity, |maximum| {
                self.capacity.min(
                    (usize::from(maximum) + usize::from(crate::socks5::MAX_UDP_HEADER_SIZE))
                        .min(usize::from(u16::MAX))
                        + 4,
                )
            })
        } else {
            self.capacity
        };
        let operation = async {
            let _waiter = observation::track(ResourceKind::Waiter);
            let reusable =
                self.reserve_reusable(business, |weight| rand::random_range(0..=weight))?;
            let reservation = match reusable {
                Some(reservation) => reservation,
                None => self.create(session, business, context).await?,
            };
            let carrier = reservation.0.clone();
            let state = {
                let _admission = self.admission.lock().unwrap();
                if self.cancel.is_cancelled() || carrier.shared.cancel.is_cancelled() {
                    return Err(closed());
                }
                let mut sessions = carrier.shared.sessions.lock().unwrap();
                let id = loop {
                    let id = rand::random::<u32>();
                    if id != 0 && !sessions.contains_key(&id) {
                        break id;
                    }
                };
                let state = State::new_for_business(
                    id,
                    receive_capacity,
                    business,
                    &carrier.shared.cancel,
                    carrier.shared.activity.clone(),
                );
                sessions.insert(id, state.clone());
                state
            };
            drop(reservation);
            Ok(RawStream::new(carrier, state, self.capacity)
                .with_queued_writes(business == Business::UdpAssociate && self.queues_datagrams()))
        };
        tokio::select! {biased;()=self.cancel.cancelled()=>Err(closed()),result=timeout_at(context.deadline(),operation)=>result.map_err(|_|io::ErrorKind::TimedOut)?}
    }
    async fn create(
        &self,
        session: StreamSession,
        business: Business,
        context: &EstablishContext,
    ) -> io::Result<Reservation> {
        let (control, control_frames) = mpsc::channel(1);
        let shared = Arc::new(Shared {
            control,
            sessions: Mutex::new(HashMap::new()),
            schedule: Mutex::new(Schedule {
                pending: 1,
                last_schedule: Instant::now(),
                disabled: None,
                closed: false,
                in_bytes: 0,
                out_bytes: 0,
            }),
            cancel: self.cancel.child_token(),
            activity: Arc::new(Notify::new()),
            idle: self.idle,
            volume: (512 * 1024 * 1024_u64) << self.factor,
            created: Instant::now(),
            udp: self.factory.config.transport == MieruTransport::Udp,
            business: self.pool(business),
            maximum_write: AtomicUsize::new(32768),
        });
        let (writer, commands) = mpsc::channel(WRITER_COMMANDS);
        // Only the isolated LOW UDP-associate pool gets default TX headroom.
        // Preserve non-default resource budgets and all per-session RX limits.
        let send_capacity = if self.factory.config.transport == MieruTransport::Udp
            && self.pool(business) == Some(Business::UdpAssociate)
            && self.capacity == 32 * 1024
        {
            96 * 1024
        } else {
            self.capacity
        };
        let carrier = Arc::new(Carrier {
            shared: shared.clone(),
            writer,
            bytes: Arc::new(Semaphore::new(send_capacity)),
        });
        let id = {
            let mut registry = self.registry.lock().unwrap();
            registry.next = registry.next.checked_add(1).ok_or_else(closed)?;
            registry.next
        };
        let (ready, connected) = oneshot::channel();
        let context = context.clone();
        let factory = self.factory.clone();
        let registry = Arc::downgrade(&self.registry);
        let deadline = context.deadline();
        let mut setup = SetupCancel(Some(shared.cancel.clone()));
        self.spawn(Box::pin(drive(
            factory,
            session,
            context,
            shared,
            commands,
            control_frames,
            ready,
            registry,
            id,
        )))?;
        timeout_at(deadline, connected)
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map_err(|_| closed())??;
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() || carrier.shared.cancel.is_cancelled() {
            return Err(closed());
        }
        self.registry
            .lock()
            .unwrap()
            .carriers
            .insert(id, carrier.clone());
        setup.0.take(); // Published ownership now belongs to registry/streams.
        Ok(Reservation(carrier))
    }
    #[cfg(test)]
    pub(super) fn attach_tcp_stream_for_test(&self) -> io::Result<RawStream> {
        // Use the real live carrier and production reservation/stream objects;
        // never let a random new-carrier bucket make sibling isolation pass.
        if self.registry.lock().unwrap().carriers.len() != 1 {
            return Err(closed());
        }
        let reservation = self
            .reserve_reusable(Business::TcpConnect, |_| 0)?
            .ok_or_else(closed)?;
        let carrier = reservation.0.clone();
        let state = {
            let _admission = self.admission.lock().unwrap();
            if self.cancel.is_cancelled() || carrier.shared.cancel.is_cancelled() {
                return Err(closed());
            }
            let mut sessions = carrier.shared.sessions.lock().unwrap();
            let mut id = 1_u32;
            while sessions.contains_key(&id) {
                id = id.checked_add(1).ok_or_else(closed)?;
            }
            let state = State::new_for_business(
                id,
                self.capacity,
                Business::TcpConnect,
                &carrier.shared.cancel,
                carrier.shared.activity.clone(),
            );
            sessions.insert(id, state.clone());
            state
        };
        drop(reservation);
        Ok(RawStream::new(carrier, state, self.capacity))
    }

    pub fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.tasks.close();
    }
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
        self.registry.lock().unwrap().carriers.clear();
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.close();
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
pub(super) fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "system clock precedes Mieru epoch",
            )
        })
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    factory: Arc<Factory>,
    session: StreamSession,
    context: EstablishContext,
    shared: Arc<Shared>,
    commands: mpsc::Receiver<WriterCommand>,
    control_frames: mpsc::Receiver<Metadata>,
    ready: oneshot::Sender<io::Result<()>>,
    registry: Weak<Mutex<Registry>>,
    id: u64,
) {
    let _pool = observation::track(ResourceKind::Pool);
    if factory.config.transport == MieruTransport::Udp {
        super::udp::drive(
            &factory.config,
            &factory.upstream,
            &factory.pattern,
            session,
            context,
            &shared,
            commands,
            ready,
        )
        .await;
        shared.fail();
        shared.sessions.lock().unwrap().clear();
        if let Some(registry) = registry.upgrade() {
            registry.lock().unwrap().carriers.remove(&id);
        }
        return;
    }
    let setup = async {
        let _handshake = observation::track(ResourceKind::Handshake);
        shared.set_maximum_write(
            factory
                .pattern
                .plaintext_fragment_limit(MieruTransport::Tcp, usize::MAX)?,
        );
        let port = rand::random_range(factory.config.port..=factory.config.port_end);
        let server = server_destination(&factory.config.address, port)?;
        let upstream = factory.upstream.for_server(&server, true);
        let io = upstream
            .connect_server(session, &server, &context)
            .await
            .map_err(|_| closed())?;
        let key = Arc::new(crypto::derive_key(
            &factory.config.username,
            &factory.config.password,
            now()?,
        ));
        let mut nonce = rand::random();
        factory
            .pattern
            .rewrite_nonce(&mut NonceState::new(), &mut nonce, MieruTransport::Tcp);
        let nonce = crypto::make_client_nonce(&factory.config.username, nonce);
        Ok::<_, io::Error>((
            io.io,
            StreamEncoder::new(key.clone(), nonce),
            StreamDecoder::new(key),
        ))
    };
    let setup = tokio::select! {biased;()=shared.cancel.cancelled()=>Err(closed()),result=timeout_at(context.deadline(),setup)=>result.map_err(|_|io::ErrorKind::TimedOut.into()).and_then(|result|result)};
    match setup {
        Ok((io, mut encoder, mut decoder)) => {
            if ready.send(Ok(())).is_ok() {
                let (mut reader, mut writer) = tokio::io::split(CountedIo {
                    io,
                    shared: shared.clone(),
                });
                tokio::select! {biased;
                    ()=shared.cancel.cancelled()=>{},
                    _=read_loop(&mut reader,&mut decoder,&shared)=>{},
                    _=write_loop(&mut writer,&mut encoder,commands,control_frames,&shared,&factory.pattern)=>{},
                    ()=idle_loop(&shared)=>{},
                }
                shared.fail();
                let _ = tokio::time::timeout(Duration::from_secs(1), writer.shutdown()).await;
                drop((reader, writer));
            }
        }
        Err(error) => {
            let _ = ready.send(Err(error));
        }
    }
    shared.fail();
    shared.sessions.lock().unwrap().clear();
    if let Some(registry) = registry.upgrade() {
        registry.lock().unwrap().carriers.remove(&id);
    }
}
async fn idle_loop(shared: &Shared) {
    let mut interval = tokio::time::interval(CLEAN_INTERVAL);
    loop {
        interval.tick().await;
        if shared.clean() {
            return;
        }
    }
}
async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    decoder: &mut StreamDecoder,
    shared: &Shared,
) -> io::Result<()> {
    while let Some(frame) = decoder.read_frame_with_clock(reader, now).await? {
        let (id, sequence, kind) = match frame.metadata {
            Metadata::Session(meta) => (meta.session_id, meta.sequence, 0_u8),
            Metadata::Data(meta) => (
                meta.session_id,
                meta.sequence,
                if meta.kind == DataKind::ServerAck {
                    1
                } else {
                    0
                },
            ),
        };
        let state = shared.sessions.lock().unwrap().get(&id).cloned();
        let Some(state) = state else {
            match frame.metadata {
                Metadata::Data(meta) => {
                    shared
                        .control
                        .send(Metadata::Session(SessionMetadata {
                            kind: SessionKind::CloseRequest,
                            session_id: id,
                            sequence: meta.unack_sequence,
                            status: 0,
                        }))
                        .await
                        .map_err(|_| closed())?;
                }
                Metadata::Session(meta) if meta.kind == SessionKind::OpenResponse => {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Metadata::Session(_) => {}
            }
            continue;
        };
        if kind == 1 {
            continue;
        }
        if sequence != state.next_receive.load(Ordering::Acquire) {
            state.finish(true);
            state.close();
            continue;
        }
        state
            .next_receive
            .store(sequence.wrapping_add(1), Ordering::Release);
        match frame.metadata {
            Metadata::Session(meta) => match meta.kind {
                SessionKind::OpenResponse => {}
                SessionKind::CloseRequest => {
                    state.close_response.store(true, Ordering::Release);
                    state.finish(meta.status != 0);
                    continue;
                }
                SessionKind::CloseResponse => {
                    state.finish(meta.status != 0);
                    shared.sessions.lock().unwrap().remove(&id);
                    continue;
                }
                SessionKind::OpenRequest => return Err(io::ErrorKind::InvalidData.into()),
            },
            Metadata::Data(meta) if meta.kind != DataKind::ServerData => {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Metadata::Data(_) => {}
        }
        // Business cancellation interrupts delivery, never the physical decoder.
        let _ = state.deliver(frame.payload).await;
    }
    Err(io::ErrorKind::UnexpectedEof.into())
}
async fn write_loop<W: AsyncWrite + Unpin>(
    writer: &mut W,
    encoder: &mut StreamEncoder,
    mut commands: mpsc::Receiver<WriterCommand>,
    mut control_frames: mpsc::Receiver<Metadata>,
    shared: &Shared,
    pattern: &EffectivePattern,
) -> io::Result<()> {
    let mut output = Vec::new();
    loop {
        tokio::select! {
            frame=control_frames.recv()=>{let Some(metadata)=frame else{return Ok(());};write_frame(writer,encoder,pattern,metadata,&[],&mut output).await?;},
            command=commands.recv()=>{
                let Some(command)=command else{return Ok(());};
                if command.state.local_closed.load(Ordering::Acquire) || command.state.remote_closed.load(Ordering::Acquire){let _=command.done.send(Err(closed()));continue;}
                let operation=async {
                    let first=!command.state.opened.swap(true,Ordering::AcqRel);
                    if first {
                        let piggyback=!pattern.low_entropy_enabled() && command.piggyback && command.data.len()<=1024;
                        let metadata=Metadata::Session(SessionMetadata{kind:SessionKind::OpenRequest,session_id:command.state.id,sequence:command.state.sequence.fetch_add(1,Ordering::AcqRel),status:0});
                        write_frame(writer,encoder,pattern,metadata,if piggyback{&command.data}else{&[]},&mut output).await?;
                        if piggyback{return Ok(());}
                    }
                    let metadata=Metadata::Data(DataMetadata{kind:DataKind::ClientData,session_id:command.state.id,sequence:command.state.sequence.fetch_add(1,Ordering::AcqRel),unack_sequence:command.state.next_receive.load(Ordering::Acquire),window:1,fragment:0});
                    write_frame(writer,encoder,pattern,metadata,&command.data,&mut output).await
                }.await;
                let failed=operation.is_err();let _=command.done.send(operation);if failed{return Err(closed());}
            },
            ()=shared.activity.notified()=>{
                let closing:Vec<_>=shared.sessions.lock().unwrap().values().filter(|state|state.local_closed.load(Ordering::Acquire)||state.remote_closed.load(Ordering::Acquire)).cloned().collect();
                for state in closing {
                    if state.opened.load(Ordering::Acquire) {
                        let kind=if state.close_response.load(Ordering::Acquire){SessionKind::CloseResponse}else{SessionKind::CloseRequest};
                        write_frame(writer,encoder,pattern,Metadata::Session(SessionMetadata{kind,session_id:state.id,sequence:state.sequence.fetch_add(1,Ordering::AcqRel),status:0}),&[],&mut output).await?;
                    }
                    shared.sessions.lock().unwrap().remove(&state.id);
                }
            },
        }
    }
}
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    encoder: &mut StreamEncoder,
    pattern: &EffectivePattern,
    metadata: Metadata,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> io::Result<()> {
    let prepared =
        pattern.prepare_frame(metadata, payload.len(), MieruTransport::Tcp, usize::MAX)?;
    encoder.encode_frame(metadata, payload, prepared.encoding(), now()?, output)?;
    // Encoding commits the directional nonce. Business cancellation cannot
    // interrupt this write or retry it; only physical Stop/failure can retire it.
    if matches!(metadata, Metadata::Session(_)) {
        for chunk in pattern.control_chunks(output.len()) {
            writer.write_all(&output[chunk.range]).await?;
            if !chunk.delay_after.is_zero() {
                tokio::time::sleep(chunk.delay_after).await;
            }
        }
    } else {
        writer.write_all(output).await?;
    }
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::super::{
        stream::Stream,
        tests::{Peer, config, echo, session},
    };
    use super::*;
    use crate::{config::MieruHandshake, resources::observation::ResourceProbe};
    #[derive(Default)]
    struct RecordedWriter {
        bytes: Vec<u8>,
        writes: Vec<usize>,
    }
    impl AsyncWrite for RecordedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push(bytes.len());
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn mieru_tcp_pattern_consumes_low_entropy_and_control_fragmentation() {
        // Independently encoded protobuf: fixed nonce prefix, no padding,
        // MODE32 low entropy and TCP control fragmentation with zero sleep.
        const PATTERN: &str = "CAAaBAgBEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=";
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peer = Peer::new(false);
                let mut configuration = config(MieruHandshake::NoWait);
                configuration.traffic_pattern = Some(PATTERN.into());
                let client =
                    Client::new(&configuration, UpstreamPath::proxy(peer.clone()), 32768).unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let raw = client
                    .open(session(), Business::TcpConnect, None, &context)
                    .await
                    .unwrap();
                let state = raw.state.clone();
                assert_eq!(
                    client
                        .registry
                        .lock()
                        .unwrap()
                        .carriers
                        .values()
                        .next()
                        .unwrap()
                        .maximum_write(),
                    32764
                );
                let mut stream: BoxStream =
                    Box::new(Stream::no_wait(raw, &session().destination, 1).unwrap());
                echo(&mut stream, b"client-first low entropy").await;
                assert_eq!(state.sequence.load(Ordering::Acquire), 2);
                echo(&mut stream, &vec![0x53; 32768]).await;
                assert_eq!(state.sequence.load(Ordering::Acquire), 4);

                let pattern = &client.factory.pattern;
                let key = Arc::new(crypto::derive_key(
                    "vole",
                    "fixture-password",
                    now().unwrap(),
                ));
                let mut encoder = StreamEncoder::new(key.clone(), rand::random());
                let mut recorded = RecordedWriter::default();
                let mut output = Vec::new();
                let control = Metadata::Session(SessionMetadata {
                    kind: SessionKind::CloseRequest,
                    session_id: 1,
                    sequence: 0,
                    status: 0,
                });
                write_frame(
                    &mut recorded,
                    &mut encoder,
                    pattern,
                    control,
                    &[],
                    &mut output,
                )
                .await
                .unwrap();
                assert!(
                    recorded.writes.len() > 1,
                    "control frame was not fragmented"
                );
                recorded.writes.clear();
                let metadata = Metadata::Data(DataMetadata {
                    kind: DataKind::ClientData,
                    session_id: 1,
                    sequence: 1,
                    unack_sequence: 0,
                    window: 1,
                    fragment: 0,
                });
                let payload = vec![0x35; 32764];
                write_frame(
                    &mut recorded,
                    &mut encoder,
                    pattern,
                    metadata,
                    &payload,
                    &mut output,
                )
                .await
                .unwrap();
                assert_eq!(recorded.writes.len(), 1, "DATA was control-fragmented");
                assert_eq!(output.len(), 48 + 65528 + 16);
                let mut decoder = StreamDecoder::new(key);
                let mut input = recorded.bytes.as_slice();
                let first = decoder
                    .read_frame_with_clock(&mut input, now)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first.metadata, control);
                let data = decoder
                    .read_frame_with_clock(&mut input, now)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(data.metadata, metadata);
                assert_eq!(data.payload, payload);
                assert!(input.is_empty());
                client.shutdown().await;
                drop((stream, state, client));
                peer.stop().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test]
    async fn mieru_tcp_low_separates_business_pools_without_changing_other_modes() {
        let probe = ResourceProbe::default();
        let outcomes: io::Result<Vec<(String, bool, bool)>> = probe
            .scope(async {
                let mut outcomes = Vec::new();
                for (
                    label,
                    transport,
                    multiplexing,
                    business,
                    active_reusable,
                    other_business_reusable,
                ) in [
                    (
                        "tcp-low",
                        MieruTransport::Tcp,
                        MieruMultiplexing::Low,
                        Business::TcpConnect,
                        false,
                        false,
                    ),
                    (
                        "udp-associate-low",
                        MieruTransport::Tcp,
                        MieruMultiplexing::Low,
                        Business::UdpAssociate,
                        true,
                        false,
                    ),
                    (
                        "middle",
                        MieruTransport::Tcp,
                        MieruMultiplexing::Middle,
                        Business::TcpConnect,
                        true,
                        true,
                    ),
                    (
                        "high",
                        MieruTransport::Tcp,
                        MieruMultiplexing::High,
                        Business::TcpConnect,
                        true,
                        true,
                    ),
                    (
                        "udp-carrier-low",
                        MieruTransport::Udp,
                        MieruMultiplexing::Low,
                        Business::TcpConnect,
                        true,
                        false,
                    ),
                    (
                        "udp-carrier-low-associate",
                        MieruTransport::Udp,
                        MieruMultiplexing::Low,
                        Business::UdpAssociate,
                        true,
                        false,
                    ),
                    (
                        "udp-carrier-middle",
                        MieruTransport::Udp,
                        MieruMultiplexing::Middle,
                        Business::TcpConnect,
                        true,
                        true,
                    ),
                    (
                        "udp-carrier-high",
                        MieruTransport::Udp,
                        MieruMultiplexing::High,
                        Business::TcpConnect,
                        true,
                        true,
                    ),
                    (
                        "udp-carrier-off",
                        MieruTransport::Udp,
                        MieruMultiplexing::Off,
                        Business::TcpConnect,
                        false,
                        false,
                    ),
                    (
                        "off",
                        MieruTransport::Tcp,
                        MieruMultiplexing::Off,
                        Business::TcpConnect,
                        false,
                        false,
                    ),
                ] {
                    let peer = Peer::new(false);
                    let mut settings = config(MieruHandshake::NoWait);
                    settings.transport = transport;
                    settings.multiplexing = multiplexing;
                    let client = Client::new(&settings, UpstreamPath::proxy(peer.clone()), 1024)?;
                    let mut shared = Shared::output_test_shared(client.cancel.child_token());
                    let settings = Arc::get_mut(&mut shared).unwrap();
                    settings.udp = transport == MieruTransport::Udp;
                    settings.business = client.pool(business);
                    let state = State::new(1, 1024, &shared.cancel, shared.activity.clone());
                    shared.sessions.lock().unwrap().insert(1, state.clone());
                    let (writer, receiver) = mpsc::channel(WRITER_COMMANDS);
                    let carrier = Arc::new(Carrier {
                        shared: shared.clone(),
                        writer,
                        bytes: Arc::new(Semaphore::new(1024)),
                    });
                    client
                        .registry
                        .lock()
                        .unwrap()
                        .carriers
                        .insert(1, carrier.clone());
                    // Call the production picker, always selecting the sole reusable bucket.
                    // No framing or network is needed to test this admission decision.
                    let result: io::Result<Vec<(String, bool, bool)>> = (|| {
                        let mut observed = Vec::new();
                        let active = client.reserve_reusable(business, |_| 0)?;
                        observed.push((
                            format!("{label} active"),
                            active.is_some(),
                            active_reusable,
                        ));
                        drop(active);
                        state.close();
                        let idle = client.reserve_reusable(business, |_| 0)?;
                        observed.push((
                            format!("{label} idle after close"),
                            idle.is_some(),
                            multiplexing != MieruMultiplexing::Off,
                        ));
                        // Keep the first reservation across the second attempt,
                        // matching the gap before Client::open inserts its session.
                        let pending = client.reserve_reusable(business, |_| 0)?;
                        observed.push((
                            format!("{label} pending"),
                            pending.is_some(),
                            active_reusable,
                        ));
                        drop(pending);
                        drop(idle);
                        let other_business = match business {
                            Business::TcpConnect => Business::UdpAssociate,
                            Business::UdpAssociate => Business::TcpConnect,
                        };
                        let other = client.reserve_reusable(other_business, |_| 0)?;
                        observed.push((
                            format!("{label} other business"),
                            other.is_some(),
                            other_business_reusable,
                        ));
                        drop(other);
                        let idle_again = client.reserve_reusable(business, |_| 0)?;
                        observed.push((
                            format!("{label} after reservation release"),
                            idle_again.is_some(),
                            multiplexing != MieruMultiplexing::Off,
                        ));
                        drop(idle_again);
                        let new_carrier = client.reserve_reusable(business, |weight| weight)?;
                        observed.push((
                            format!("{label} new carrier bucket"),
                            new_carrier.is_some(),
                            false,
                        ));
                        drop(new_carrier);
                        Ok(observed)
                    })();
                    client.shutdown().await;
                    drop((client, carrier, shared, state, receiver));
                    peer.stop().await;
                    outcomes.extend(result?);
                }
                Ok(outcomes)
            })
            .await;
        // Check decisions only after every owner has been stopped/dropped.
        assert!(probe.snapshot().is_idle());
        for (label, actual, expected) in outcomes.unwrap() {
            assert_eq!(actual, expected, "{label}");
        }
    }
    #[tokio::test]
    async fn mieru_tcp_low_udp_associate_uses_active_pool_from_outbound_callsite() {
        use crate::{
            outbound::{DatagramRequest, OutboundConnector},
            session::DatagramSession,
        };
        let probe = ResourceProbe::default();
        let active_reusable = probe
            .scope(async {
                let peer = Peer::new(false);
                let mut settings = config(MieruHandshake::Standard);
                settings.multiplexing = MieruMultiplexing::Low;
                let node = super::super::MieruOutbound::new(
                    &settings,
                    UpstreamPath::proxy(peer.clone()),
                    1024,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let request =
                    DatagramRequest::new(DatagramSession::for_tun(session().source, 1500));
                let mut packet = node.open_datagram(request, &context).await.unwrap();
                assert_eq!(peer.calls.load(Ordering::Acquire), 1);
                // Exercise the actual outbound's published carrier, choosing the
                // reuse bucket deterministically while its UDP session is active.
                let reusable = node
                    .client
                    .reserve_reusable(Business::UdpAssociate, |_| 0)
                    .unwrap();
                let active_reusable = reusable.is_some();
                drop(reusable);
                packet.close().await.unwrap();
                drop(packet);
                node.shutdown().await;
                drop(node);
                peer.stop().await;
                active_reusable
            })
            .await;
        assert!(probe.snapshot().is_idle());
        assert!(
            active_reusable,
            "LOW UDP Associate must retain active reuse"
        );
    }
    #[tokio::test]
    async fn mieru_tcp_low_slow_reader_does_not_block_tcp_or_udp_siblings() {
        use crate::{
            dispatch::DispatchError,
            outbound::{DatagramRequest, OutboundConnector},
            session::{Datagram, DatagramSession, Destination},
        };
        use tokio::io::AsyncReadExt;

        let probe = ResourceProbe::default();
        let (blocked, exhausted, siblings) = probe
            .scope(async {
                let peer = Peer::new(false);
                let mut settings = config(MieruHandshake::Standard);
                settings.multiplexing = MieruMultiplexing::Low;
                let node = super::super::MieruOutbound::new(
                    &settings,
                    UpstreamPath::proxy(peer.clone()),
                    1024,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let first = node.connect_stream(session(), &context).await.unwrap();
                let carrier = node
                    .client
                    .registry
                    .lock()
                    .unwrap()
                    .carriers
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                let state = carrier
                    .shared
                    .sessions
                    .lock()
                    .unwrap()
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                let (reader, mut writer) = tokio::io::split(first.io);
                let payload = vec![7; 16384];
                let (blocked, exhausted, siblings) = {
                    // Hold the read half without consuming the echoed bytes. The
                    // real decoder fills its unchanged 1 KiB receive budget.
                    let writing = writer.write_all(&payload);
                    tokio::pin!(writing);
                    let blocked = tokio::time::timeout(Duration::from_millis(20), &mut writing)
                        .await
                        .is_err();
                    let exhausted = state.receive_bytes.available_permits() == 0;
                    let siblings = tokio::time::timeout(Duration::from_secs(3), async {
                        let mut sibling = node.connect_stream(session(), &context).await?.io;
                        sibling.write_all(b"sibling").await?;
                        let mut echoed = [0; 7];
                        sibling.read_exact(&mut echoed).await?;
                        let request =
                            DatagramRequest::new(DatagramSession::for_tun(session().source, 1500));
                        let mut packet = node.open_datagram(request, &context).await?;
                        let remote = Destination::Ip("198.51.100.1:53".parse().unwrap());
                        packet
                            .send(Datagram {
                                remote: remote.clone(),
                                payload: Bytes::from_static(b"packet"),
                                sniffed_domain: None,
                            })
                            .await?;
                        let response = packet.receive().await?;
                        packet.close().await?;
                        Ok::<_, DispatchError>(
                            echoed == *b"sibling"
                                && response.remote == remote
                                && response.payload == b"packet"[..],
                        )
                    })
                    .await;
                    (blocked, exhausted, siblings)
                };
                drop((reader, writer, state, carrier));
                node.shutdown().await;
                drop(node);
                peer.stop().await;
                (blocked, exhausted, siblings)
            })
            .await;
        assert!(probe.snapshot().is_idle());
        assert!(
            blocked,
            "the unread stream must apply physical backpressure"
        );
        assert!(
            exhausted,
            "the unread stream must exhaust its original receive budget"
        );
        assert!(
            siblings.unwrap().unwrap(),
            "TCP and UDP siblings must retain their data"
        );
    }
    #[tokio::test]
    async fn mieru_tcp_shared_carrier_preserves_sibling_and_bounded_reader() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peer = Peer::new(false);
                let client = Client::new(
                    &config(MieruHandshake::NoWait),
                    UpstreamPath::proxy(peer.clone()),
                    32768,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let raw = client
                    .open(session(), Business::TcpConnect, None, &context)
                    .await
                    .unwrap();
                let target = session().destination;
                let mut first: BoxStream = Box::new(Stream::no_wait(raw, &target, 1).unwrap());
                echo(&mut first, &vec![1; 8192]).await;
                // Pin this second business session to the actual published carrier
                // so probabilistic scheduling cannot make the wire fixture flaky.
                let carrier = client
                    .registry
                    .lock()
                    .unwrap()
                    .carriers
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                assert!(carrier.shared.reserve(false));
                let reservation = Reservation(carrier.clone());
                let id = loop {
                    let id = rand::random::<u32>();
                    if id != 0 && !carrier.shared.sessions.lock().unwrap().contains_key(&id) {
                        break id;
                    }
                };
                let state = State::new(
                    id,
                    client.capacity,
                    &carrier.shared.cancel,
                    carrier.shared.activity.clone(),
                );
                carrier
                    .shared
                    .sessions
                    .lock()
                    .unwrap()
                    .insert(id, state.clone());
                drop(reservation);
                let raw = RawStream::new(carrier.clone(), state, client.capacity);
                let mut second: BoxStream = Box::new(Stream::no_wait(raw, &target, 1).unwrap());
                echo(&mut second, b"second-session").await;
                assert_eq!(peer.calls.load(Ordering::Acquire), 1);
                drop(first);
                echo(&mut second, b"sibling-after-close").await;
                assert!(carrier.bytes.available_permits() <= client.capacity);
                client.shutdown().await;
                drop((second, carrier, client));
                peer.stop().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test(start_paused = true)]
    async fn mieru_tcp_scheduler_drains_without_killing_active_session() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peer = Peer::new(false);
                let client = Client::new(
                    &config(MieruHandshake::NoWait),
                    UpstreamPath::proxy(peer.clone()),
                    1024,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let raw = client
                    .open(session(), Business::TcpConnect, None, &context)
                    .await
                    .unwrap();
                let carrier = client
                    .registry
                    .lock()
                    .unwrap()
                    .carriers
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                let mut io: BoxStream =
                    Box::new(Stream::no_wait(raw, &session().destination, 1).unwrap());
                echo(&mut io, b"active").await;
                carrier.shared.schedule.lock().unwrap().out_bytes = carrier.shared.volume + 1;
                assert!(!carrier.shared.clean());
                assert!(!carrier.shared.reserve(false));
                echo(&mut io, b"after-scheduling-disabled").await;
                drop(io);
                tokio::time::advance(client.idle + CLEAN_INTERVAL).await;
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !carrier.shared.cancel.is_cancelled() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                client.shutdown().await;
                drop((carrier, client));
                peer.stop().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test(start_paused = true)]
    async fn mieru_udp_carrier_age_disables_new_reservations_and_drains() {
        let cancellation = CancellationToken::new();
        let activity = Arc::new(Notify::new());
        let state = State::new(1, 32768, &cancellation, activity.clone());
        let (control, _) = mpsc::channel(1);
        let shared = Shared {
            sessions: Mutex::new(HashMap::from([(1, state.clone())])),
            control,
            schedule: Mutex::new(Schedule {
                pending: 0,
                last_schedule: Instant::now(),
                disabled: None,
                closed: false,
                in_bytes: 0,
                out_bytes: 0,
            }),
            cancel: cancellation,
            activity,
            idle: Duration::from_secs(150),
            volume: 512 * 1024 * 1024,
            created: Instant::now(),
            udp: true,
            business: None,
            maximum_write: AtomicUsize::new(32768),
        };
        // A lazy NO_WAIT connection may be dropped without ever submitting a write.
        let unopened = State::new(2, 32768, &shared.cancel, shared.activity.clone());
        shared.sessions.lock().unwrap().insert(2, unopened.clone());
        unopened.close();
        shared.reap_unopened();
        assert_eq!(shared.sessions.lock().unwrap().len(), 1);
        assert!(shared.sessions.lock().unwrap().contains_key(&1));
        drop(unopened);
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(!shared.clean());
        assert!(shared.reserve(false));
        shared.release();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!shared.clean());
        assert!(!shared.reserve(false));
        assert!(!state.cancel.is_cancelled());
        state.close();
        tokio::time::advance(Duration::from_secs(150)).await;
        assert!(shared.clean());
    }
}
