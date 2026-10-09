use std::{
    collections::{BTreeMap, HashMap},
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    dispatch::{BoxStream, DispatchError},
    outbound::EstablishContext,
    session::{Destination, StreamSession},
};

use super::{
    padding::PaddingScheme,
    session::{PreparedSession, Session},
    stream::AnyTlsStream,
};
use crate::outbound::uot::UotTransport;

const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[async_trait]
pub(crate) trait SessionDialer: Send + Sync {
    async fn connect(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError>;
}

#[derive(Default)]
struct ClientState {
    closed: bool,
    cleanup_started: bool,
    sessions: HashMap<u64, Arc<Session>>,
    idle: BTreeMap<u64, tokio::time::Instant>,
}

pub(crate) struct AnyTlsClient {
    dialer: Arc<dyn SessionDialer>,
    password_hash: [u8; 32],
    padding: Arc<ArcSwap<PaddingScheme>>,
    max_stream_chunk: usize,
    incoming_capacity: usize,
    next_sequence: AtomicU64,
    state: Mutex<ClientState>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
}

impl std::fmt::Debug for AnyTlsClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        formatter
            .debug_struct("AnyTlsClient")
            .field("closed", &state.closed)
            .field("session_count", &state.sessions.len())
            .field("idle_count", &state.idle.len())
            .field("max_stream_chunk", &self.max_stream_chunk)
            .finish_non_exhaustive()
    }
}

impl AnyTlsClient {
    pub(crate) fn new(
        dialer: Arc<dyn SessionDialer>,
        password: &str,
        stream_buffer_capacity: usize,
    ) -> io::Result<Arc<Self>> {
        if password.is_empty() || password.len() > 1_024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS password must contain between 1 and 1024 UTF-8 bytes",
            ));
        }
        if stream_buffer_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS stream buffer capacity must be greater than zero",
            ));
        }
        let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let max_stream_chunk = stream_buffer_capacity.min(usize::from(u16::MAX));
        let incoming_capacity = stream_buffer_capacity.div_ceil(max_stream_chunk).max(1);
        let client = Arc::new(Self {
            dialer,
            password_hash,
            padding: Arc::new(ArcSwap::from_pointee(PaddingScheme::default_scheme())),
            max_stream_chunk,
            incoming_capacity,
            next_sequence: AtomicU64::new(0),
            state: Mutex::new(ClientState::default()),
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
        });
        Ok(client)
    }

    pub(crate) async fn open_stream(
        self: &Arc<Self>,
        session: StreamSession,
        target: &Destination,
        context: &EstablishContext,
    ) -> Result<AnyTlsStream, DispatchError> {
        self.ensure_cleanup()?;
        if let Some(idle) = self.take_idle() {
            match idle.open_reused(target, context, &self.tasks).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    tracing::debug!(error = %error, "discarded stale AnyTLS idle session");
                }
            }
        }
        self.open_fresh(session, target, context).await
    }

    async fn open_fresh(
        self: &Arc<Self>,
        session: StreamSession,
        target: &Destination,
        context: &EstablishContext,
    ) -> Result<AnyTlsStream, DispatchError> {
        let sequence = self
            .next_sequence
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| DispatchError::Other("AnyTLS session sequence exhausted".to_owned()))?
            + 1;
        let transport = self.dialer.connect(session, context).await?;
        let padding_snapshot = self.padding.load_full();
        let prepared = context
            .run_io(
                "AnyTLS authentication and session preface",
                Session::prepare_first(
                    sequence,
                    Arc::downgrade(self),
                    transport,
                    self.password_hash,
                    padding_snapshot,
                    self.padding.clone(),
                    target,
                    self.max_stream_chunk,
                    self.incoming_capacity,
                    &self.cancellation,
                ),
            )
            .await?;
        self.register_and_start(prepared)
    }

    fn register_and_start(
        self: &Arc<Self>,
        prepared: PreparedSession,
    ) -> Result<AnyTlsStream, DispatchError> {
        let session = prepared.session();
        let stream = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed {
                drop(state);
                session.begin_shutdown();
                return Err(DispatchError::Other("AnyTLS client is closed".to_owned()));
            }
            state.sessions.insert(session.sequence(), session.clone());
            prepared.start(&self.tasks)
        };
        if session.is_closed() {
            self.session_closed(session.sequence());
            return Err(DispatchError::Other(
                "AnyTLS session closed during startup".to_owned(),
            ));
        }
        Ok(stream)
    }

    pub(crate) fn start_uot(
        &self,
        stream: AnyTlsStream,
        max_response_payload_size: u16,
    ) -> Result<UotTransport, DispatchError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(DispatchError::Other("AnyTLS client is closed".to_owned()));
        }
        let (reader, writer) = tokio::io::split(stream);
        Ok(UotTransport::new(
            reader,
            writer,
            max_response_payload_size,
            self.cancellation.clone(),
            &self.tasks,
        ))
    }

    fn take_idle(&self) -> Option<Arc<Session>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some((sequence, _)) = state.idle.pop_last() {
            let Some(session) = state.sessions.get(&sequence).cloned() else {
                continue;
            };
            if !session.is_closed() {
                return Some(session);
            }
        }
        None
    }

    pub(crate) fn return_idle(&self, session: &Arc<Session>) {
        let mut close = false;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed || session.is_closed() {
                close = true;
            } else if state.sessions.contains_key(&session.sequence()) {
                state
                    .idle
                    .insert(session.sequence(), tokio::time::Instant::now());
            } else {
                close = true;
            }
        }
        if close {
            session.begin_shutdown();
        }
    }

    pub(crate) fn session_closed(&self, sequence: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sessions.remove(&sequence);
        state.idle.remove(&sequence);
    }

    pub(crate) fn begin_shutdown(&self) {
        let sessions = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed {
                Vec::new()
            } else {
                state.closed = true;
                state.idle.clear();
                state.sessions.values().cloned().collect::<Vec<_>>()
            }
        };
        self.cancellation.cancel();
        for session in sessions {
            session.begin_shutdown();
        }
        self.tasks.close();
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
    }

    fn ensure_cleanup(self: &Arc<Self>) -> Result<(), DispatchError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(DispatchError::Other("AnyTLS client is closed".to_owned()));
        }
        if !state.cleanup_started {
            // Graph construction must not leave a task behind on a later
            // constructor/bind failure. Start only when traffic first uses
            // this node, under the same lock as the shutdown admission gate.
            state.cleanup_started = true;
            self.tasks
                .spawn(crate::resources::observation::task(cleanup_idle(
                    Arc::downgrade(self),
                    self.cancellation.clone(),
                )));
        }
        Ok(())
    }

    fn expire_idle(&self, now: tokio::time::Instant) -> Vec<Arc<Session>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut expired_sequences = Vec::new();
        for (&sequence, &idle_since) in &state.idle {
            if now.duration_since(idle_since) >= IDLE_TIMEOUT {
                expired_sequences.push(sequence);
            }
        }
        for sequence in &expired_sequences {
            state.idle.remove(sequence);
        }
        expired_sequences
            .into_iter()
            .filter_map(|sequence| state.sessions.get(&sequence).cloned())
            .collect()
    }
}

impl Drop for AnyTlsClient {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.close();
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for session in state.sessions.values() {
            session.begin_shutdown();
        }
    }
}

async fn cleanup_idle(client: Weak<AnyTlsClient>, cancellation: CancellationToken) {
    let mut interval = tokio::time::interval(IDLE_CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            _ = interval.tick() => {
                let Some(client) = client.upgrade() else {
                    return;
                };
                let expired = client.expire_idle(tokio::time::Instant::now());
                for session in expired {
                    session.begin_shutdown();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::session::InboundKind;

    use super::*;
    use crate::outbound::anytls::frame::{Command, Frame, read_frame};

    #[derive(Clone, Copy)]
    enum ServerMode {
        V1,
        V2,
        V2Burst,
        V2NoReuseAck,
        V2RejectSecondStream,
    }

    struct DuplexDialer {
        mode: ServerMode,
        connections: AtomicUsize,
        opens: Arc<Mutex<Vec<(usize, u32)>>>,
        burst_sent: Arc<AtomicUsize>,
    }

    impl DuplexDialer {
        fn new(mode: ServerMode) -> Arc<Self> {
            Arc::new(Self {
                mode,
                connections: AtomicUsize::new(0),
                opens: Arc::new(Mutex::new(Vec::new())),
                burst_sent: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn connection_count(&self) -> usize {
            self.connections.load(Ordering::Acquire)
        }

        fn last_open(&self) -> Option<(usize, u32)> {
            self.opens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .last()
                .copied()
        }

        fn burst_sent(&self) -> bool {
            self.burst_sent.load(Ordering::Acquire) != 0
        }
    }

    #[async_trait]
    impl SessionDialer for DuplexDialer {
        async fn connect(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<BoxStream, DispatchError> {
            let connection = self.connections.fetch_add(1, Ordering::AcqRel) + 1;
            let (client, server) = tokio::io::duplex(128 * 1024);
            tokio::spawn(run_server(
                server,
                self.mode,
                connection,
                self.opens.clone(),
                self.burst_sent.clone(),
            ));
            Ok(Box::new(client))
        }
    }

    async fn run_server(
        mut stream: tokio::io::DuplexStream,
        mode: ServerMode,
        connection: usize,
        opens: Arc<Mutex<Vec<(usize, u32)>>>,
        burst_sent: Arc<AtomicUsize>,
    ) {
        let mut password_hash = [0_u8; 32];
        if stream.read_exact(&mut password_hash).await.is_err() {
            return;
        }
        let Ok(padding_length) = stream.read_u16().await else {
            return;
        };
        let mut padding_remaining = usize::from(padding_length);
        let mut drain = [0_u8; 256];
        while padding_remaining != 0 {
            let length = padding_remaining.min(drain.len());
            if stream.read_exact(&mut drain[..length]).await.is_err() {
                return;
            }
            padding_remaining -= length;
        }

        let mut first_target_seen = false;
        while let Ok(frame) = read_frame(&mut stream).await {
            match frame.command {
                Command::Settings if !matches!(mode, ServerMode::V1) => {
                    if write_server_frame(
                        &mut stream,
                        Frame::with_payload(Command::ServerSettings, 0, Bytes::from_static(b"v=2"))
                            .unwrap(),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
                Command::Syn if !matches!(mode, ServerMode::V1) => {
                    opens
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((connection, frame.stream_id));
                    let reject = matches!(mode, ServerMode::V2RejectSecondStream)
                        && connection == 1
                        && frame.stream_id == 2;
                    let acknowledgement = if reject {
                        Frame::with_payload(
                            Command::SynAck,
                            frame.stream_id,
                            Bytes::from_static(b"rejected"),
                        )
                        .unwrap()
                    } else {
                        Frame::empty(Command::SynAck, frame.stream_id)
                    };
                    let suppress_ack =
                        matches!(mode, ServerMode::V2NoReuseAck) && frame.stream_id >= 2;
                    if !suppress_ack
                        && write_server_frame(&mut stream, acknowledgement)
                            .await
                            .is_err()
                    {
                        return;
                    }
                    if reject {
                        let _ = write_server_frame(
                            &mut stream,
                            Frame::empty(Command::Fin, frame.stream_id),
                        )
                        .await;
                    }
                }
                Command::Syn => {
                    opens
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((connection, frame.stream_id));
                }
                Command::Push if frame.stream_id == 1 && !first_target_seen => {
                    first_target_seen = true;
                    if matches!(mode, ServerMode::V2Burst) {
                        for payload in [b"first".as_slice(), b"second".as_slice()] {
                            if write_server_frame(
                                &mut stream,
                                Frame::with_payload(
                                    Command::Push,
                                    frame.stream_id,
                                    Bytes::copy_from_slice(payload),
                                )
                                .unwrap(),
                            )
                            .await
                            .is_err()
                            {
                                return;
                            }
                        }
                        burst_sent.store(1, Ordering::Release);
                    } else if write_server_frame(
                        &mut stream,
                        Frame::with_payload(
                            Command::Push,
                            frame.stream_id,
                            Bytes::from_static(b"ready"),
                        )
                        .unwrap(),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    async fn write_server_frame(
        stream: &mut tokio::io::DuplexStream,
        frame: Frame,
    ) -> io::Result<()> {
        stream.write_all(&frame.encode()?).await?;
        stream.flush().await
    }

    fn stream_session() -> StreamSession {
        StreamSession {
            inbound: InboundKind::Http,
            source: "127.0.0.1:12000".parse().unwrap(),
            destination: Destination::domain("target.example", 443).unwrap(),
            sniffed_domain: None,
        }
    }

    async fn open_stream(client: &Arc<AnyTlsClient>) -> Result<AnyTlsStream, DispatchError> {
        let session = stream_session();
        let target = session.destination.clone();
        client
            .open_stream(session, &target, &EstablishContext::default())
            .await
    }

    async fn wait_until_ready(stream: &mut AnyTlsStream) {
        let mut ready = [0_u8; 5];
        tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"ready");
    }

    #[tokio::test]
    async fn group_switch_preserves_idle_pool_path_but_fresh_sessions_use_new_upstream() {
        use crate::{
            dialer::Dialer,
            dispatch::DatagramTransport,
            outbound::{
                ConnectedStream, DatagramRequest, OutboundConnector, SelectUpstream,
                SelectUpstreamMember, UpstreamPath,
            },
        };

        struct Endpoint(Arc<DuplexDialer>);
        #[async_trait]
        impl OutboundConnector for Endpoint {
            async fn connect_stream(
                &self,
                session: StreamSession,
                context: &EstablishContext,
            ) -> Result<ConnectedStream, DispatchError> {
                let peer = session.destination.clone();
                Ok(ConnectedStream {
                    io: self.0.connect(session, context).await?,
                    effective_peer: peer,
                })
            }
            async fn open_datagram(
                &self,
                _request: DatagramRequest,
                _context: &EstablishContext,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                panic!("AnyTLS UoT uses the upstream TCP path, not its datagram capability")
            }
        }
        struct GroupDialer(UpstreamPath);
        #[async_trait]
        impl SessionDialer for GroupDialer {
            async fn connect(
                &self,
                session: StreamSession,
                context: &EstablishContext,
            ) -> Result<BoxStream, DispatchError> {
                Ok(self
                    .0
                    .connect_server(
                        session,
                        &Destination::domain("anytls.invalid", 443).unwrap(),
                        context,
                    )
                    .await?
                    .io)
            }
        }
        let first = DuplexDialer::new(ServerMode::V2);
        let second = DuplexDialer::new(ServerMode::V2);
        let selection = Arc::new(crate::routing::GroupSelection::new(0));
        let group = Arc::new(SelectUpstream::new(
            selection.clone(),
            vec![
                SelectUpstreamMember::Proxy(Arc::new(Endpoint(first.clone()))),
                SelectUpstreamMember::Proxy(Arc::new(Endpoint(second.clone()))),
            ],
        ));
        let client = AnyTlsClient::new(
            Arc::new(GroupDialer(UpstreamPath::Group {
                group,
                endpoint: None,
                dialer: Dialer::default(),
            })),
            "password",
            1024,
        )
        .unwrap();
        let mut original = open_stream(&client).await.unwrap();
        wait_until_ready(&mut original).await;
        original.shutdown().await.unwrap();
        selection.store(1, Ordering::Release);
        let mut reused = open_stream(&client).await.unwrap();
        assert_eq!(
            (first.connection_count(), second.connection_count()),
            (1, 0)
        );
        let mut fresh = open_stream(&client).await.unwrap();
        wait_until_ready(&mut fresh).await;
        assert_eq!(
            (first.connection_count(), second.connection_count()),
            (1, 1)
        );
        reused.shutdown().await.unwrap();
        fresh.shutdown().await.unwrap();
        client.shutdown().await;
    }

    #[tokio::test]
    async fn v2_reuses_latest_idle_session() {
        let dialer = DuplexDialer::new(ServerMode::V2);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1_024).unwrap();

        let mut first = open_stream(&client).await.unwrap();
        wait_until_ready(&mut first).await;
        first.shutdown().await.unwrap();

        let mut reused = tokio::time::timeout(Duration::from_secs(1), open_stream(&client))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dialer.connection_count(), 1);
        reused.shutdown().await.unwrap();
        client.shutdown().await;
    }

    #[test]
    fn unused_client_needs_no_runtime_and_leaves_no_background_task() {
        let client =
            AnyTlsClient::new(DuplexDialer::new(ServerMode::V2), "password", 1024).unwrap();
        assert!(client.tasks.is_empty());
        let weak = Arc::downgrade(&client);
        client.begin_shutdown();
        assert!(client.tasks.is_empty());
        drop(client);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn idle_session_expires_at_thirty_seconds_without_returning_failed_session_to_pool() {
        let dialer = DuplexDialer::new(ServerMode::V2);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1024).unwrap();
        let mut stream = open_stream(&client).await.unwrap();
        wait_until_ready(&mut stream).await;
        stream.shutdown().await.unwrap();
        let idle_since = *client.state.lock().unwrap().idle.values().next().unwrap();
        assert!(
            client
                .expire_idle(idle_since + Duration::from_secs(29))
                .is_empty()
        );
        let expired = client.expire_idle(idle_since + Duration::from_secs(30));
        assert_eq!(expired.len(), 1);
        for session in expired {
            session.begin_shutdown();
        }
        let mut fresh = open_stream(&client).await.unwrap();
        assert_eq!(dialer.connection_count(), 2);
        fresh.shutdown().await.unwrap();
        client.shutdown().await;
        assert!(client.tasks.is_empty());
        assert_eq!(IDLE_CHECK_INTERVAL, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn missing_server_settings_falls_back_to_v1_without_syn_ack() {
        let dialer = DuplexDialer::new(ServerMode::V1);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1_024).unwrap();

        let mut first = open_stream(&client).await.unwrap();
        wait_until_ready(&mut first).await;
        first.shutdown().await.unwrap();

        let mut reused = tokio::time::timeout(Duration::from_millis(200), open_stream(&client))
            .await
            .expect("v1 fallback must not wait for SYNACK")
            .unwrap();
        assert_eq!(dialer.connection_count(), 1);
        reused.shutdown().await.unwrap();
        client.shutdown().await;
    }

    #[tokio::test]
    async fn rejected_reused_stream_fails_after_open_and_the_next_open_is_fresh() {
        let dialer = DuplexDialer::new(ServerMode::V2RejectSecondStream);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1_024).unwrap();

        let mut first = open_stream(&client).await.unwrap();
        wait_until_ready(&mut first).await;
        first.shutdown().await.unwrap();

        let mut rejected = tokio::time::timeout(Duration::from_millis(200), open_stream(&client))
            .await
            .expect("reused open must not block waiting for SYNACK")
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), rejected.read_u8())
            .await
            .expect("the rejected stream must fail promptly")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(dialer.connection_count(), 1);

        let mut fresh = open_stream(&client).await.unwrap();
        wait_until_ready(&mut fresh).await;
        assert_eq!(dialer.connection_count(), 2);
        fresh.shutdown().await.unwrap();
        client.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_cancels_active_session_tasks() {
        let dialer = DuplexDialer::new(ServerMode::V2);
        let client = AnyTlsClient::new(dialer, "password", 1_024).unwrap();
        let mut stream = open_stream(&client).await.unwrap();
        wait_until_ready(&mut stream).await;

        tokio::time::timeout(Duration::from_secs(1), client.shutdown())
            .await
            .expect("AnyTLS shutdown must not wait on active stream queues");
        assert!(stream.write_all(b"after shutdown").await.is_err());
    }

    #[tokio::test]
    async fn reuse_prefers_the_highest_sequence_even_if_it_became_idle_first() {
        let dialer = DuplexDialer::new(ServerMode::V2);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1_024).unwrap();

        let mut first = open_stream(&client).await.unwrap();
        wait_until_ready(&mut first).await;
        let mut second = open_stream(&client).await.unwrap();
        wait_until_ready(&mut second).await;
        assert_eq!(dialer.connection_count(), 2);

        second.shutdown().await.unwrap();
        first.shutdown().await.unwrap();
        let mut reused = open_stream(&client).await.unwrap();
        assert_eq!(dialer.last_open(), Some((2, 2)));

        reused.shutdown().await.unwrap();
        client.shutdown().await;
    }

    #[tokio::test]
    async fn missing_reuse_ack_closes_the_returned_stream_and_next_open_is_fresh() {
        let dialer = DuplexDialer::new(ServerMode::V2NoReuseAck);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1_024).unwrap();

        let mut first = open_stream(&client).await.unwrap();
        wait_until_ready(&mut first).await;
        first.shutdown().await.unwrap();

        let mut unacknowledged =
            tokio::time::timeout(Duration::from_millis(200), open_stream(&client))
                .await
                .expect("reused open must return before SYNACK")
                .unwrap();
        assert_eq!(dialer.connection_count(), 1);
        let error = tokio::time::timeout(Duration::from_secs(4), unacknowledged.read_u8())
            .await
            .expect("the SYNACK watchdog must close the stream")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let mut fresh = open_stream(&client).await.unwrap();
        wait_until_ready(&mut fresh).await;
        assert_eq!(dialer.connection_count(), 2);

        fresh.shutdown().await.unwrap();
        client.shutdown().await;
    }

    #[tokio::test]
    async fn local_close_unblocks_a_full_old_stream_queue_before_reuse() {
        let dialer = DuplexDialer::new(ServerMode::V2Burst);
        let client = AnyTlsClient::new(dialer.clone(), "password", 1_024).unwrap();
        let mut first = open_stream(&client).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while !dialer.burst_sent() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        tokio::time::timeout(Duration::from_secs(1), first.shutdown())
            .await
            .expect("local FIN must cancel blocked delivery to the old stream")
            .unwrap();
        let mut reused = tokio::time::timeout(Duration::from_secs(1), open_stream(&client))
            .await
            .expect("the reader loop must be free to process the reused stream SYNACK")
            .unwrap();
        assert_eq!(dialer.connection_count(), 1);

        reused.shutdown().await.unwrap();
        client.shutdown().await;
    }
}
