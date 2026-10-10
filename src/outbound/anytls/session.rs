use std::{
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _},
    sync::{mpsc, oneshot},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    dispatch::{BoxStream, DispatchError},
    outbound::EstablishContext,
    session::Destination,
    socks5::encode_address,
};

use super::{
    client::AnyTlsClient,
    frame::{Command, Frame, encode_batch, read_frame},
    padding::{PaddingScheme, write_packet},
    stream::{AnyTlsStream, StreamEvent, StreamFailure, StreamShared},
};

const STATE_ACTIVE: u8 = 0;
const STATE_IDLE: u8 = 1;
const STATE_CLOSED: u8 = 2;
const WRITER_QUEUE_CAPACITY: usize = 2;
const SYN_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DIAGNOSTIC_BYTES: usize = 256;

pub(crate) enum WriterCommand {
    Open {
        stream_id: u32,
        batch: Bytes,
        done: oneshot::Sender<io::Result<()>>,
    },
    Data {
        stream_id: u32,
        payload: Bytes,
        done: oneshot::Sender<io::Result<()>>,
    },
    Flush {
        done: oneshot::Sender<io::Result<()>>,
    },
    CloseStream {
        stream_id: u32,
        send_fin: bool,
        done: Option<oneshot::Sender<io::Result<()>>>,
    },
    Control(Frame),
}

struct ActiveStream {
    stream_id: u32,
    incoming: mpsc::Sender<StreamEvent>,
    shared: Arc<StreamShared>,
    syn_ack: Option<oneshot::Sender<io::Result<()>>>,
}

pub(crate) struct Session {
    sequence: u64,
    client: Weak<AnyTlsClient>,
    state: AtomicU8,
    closed: AtomicBool,
    next_stream_id: AtomicU32,
    peer_version: AtomicU8,
    packet_counter: AtomicU32,
    active: Mutex<Option<ActiveStream>>,
    writer: mpsc::Sender<WriterCommand>,
    cancellation: CancellationToken,
    padding_snapshot: Arc<PaddingScheme>,
    client_padding: Arc<ArcSwap<PaddingScheme>>,
    max_stream_chunk: usize,
    incoming_capacity: usize,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsSession")
            .field("sequence", &self.sequence)
            .field("state", &self.state.load(Ordering::Acquire))
            .field("peer_version", &self.peer_version.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

pub(crate) struct PreparedSession {
    session: Arc<Session>,
    stream: AnyTlsStream,
    transport: BoxStream,
    writer_receiver: mpsc::Receiver<WriterCommand>,
}

struct ReusedOpenGuard {
    session: Arc<Session>,
    committed: bool,
}

impl ReusedOpenGuard {
    fn new(session: Arc<Session>) -> Self {
        Self {
            session,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ReusedOpenGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.session.fail(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS reused stream open was cancelled",
            ));
        }
    }
}

impl PreparedSession {
    pub(crate) fn session(&self) -> Arc<Session> {
        self.session.clone()
    }

    pub(crate) fn start(self, tracker: &TaskTracker) -> AnyTlsStream {
        let Self {
            session,
            stream,
            transport,
            writer_receiver,
        } = self;
        let (reader, writer) = tokio::io::split(transport);
        tracker.spawn(crate::resources::observation::task(reader_loop(
            session.clone(),
            reader,
        )));
        tracker.spawn(crate::resources::observation::task(writer_loop(
            session,
            writer,
            writer_receiver,
        )));
        stream
    }
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare_first(
        sequence: u64,
        client: Weak<AnyTlsClient>,
        mut transport: BoxStream,
        password_hash: [u8; 32],
        padding_snapshot: Arc<PaddingScheme>,
        client_padding: Arc<ArcSwap<PaddingScheme>>,
        target: &Destination,
        client_metadata: &str,
        max_stream_chunk: usize,
        incoming_capacity: usize,
        parent_cancellation: &CancellationToken,
    ) -> io::Result<PreparedSession> {
        let padding_length = padding_snapshot.authentication_padding_length();
        let mut authentication = BytesMut::with_capacity(32 + 2 + usize::from(padding_length));
        authentication.extend_from_slice(&password_hash);
        authentication.extend_from_slice(&padding_length.to_be_bytes());
        authentication.resize(authentication.len() + usize::from(padding_length), 0);
        transport.write_all(&authentication).await?;
        transport.flush().await?;

        let first_batch = first_stream_batch(&padding_snapshot, target, client_metadata)?;
        write_packet(&mut transport, &padding_snapshot, 1, &first_batch).await?;

        let (writer, writer_receiver) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        let (active, stream_receiver, shared, _ack_receiver) =
            make_active_stream(1, incoming_capacity);
        let session = Arc::new(Self {
            sequence,
            client,
            state: AtomicU8::new(STATE_ACTIVE),
            closed: AtomicBool::new(false),
            next_stream_id: AtomicU32::new(1),
            peer_version: AtomicU8::new(1),
            packet_counter: AtomicU32::new(2),
            active: Mutex::new(Some(active)),
            writer,
            cancellation: parent_cancellation.child_token(),
            padding_snapshot,
            client_padding,
            max_stream_chunk,
            incoming_capacity,
        });
        let stream = AnyTlsStream::new(
            session.clone(),
            1,
            stream_receiver,
            shared,
            max_stream_chunk,
        );
        Ok(PreparedSession {
            session,
            stream,
            transport,
            writer_receiver,
        })
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn writer(&self) -> mpsc::Sender<WriterCommand> {
        self.writer.clone()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn try_mark_active(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_IDLE,
                STATE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub(crate) async fn open_reused(
        self: &Arc<Self>,
        target: &Destination,
        context: &EstablishContext,
        tracker: &TaskTracker,
    ) -> Result<AnyTlsStream, DispatchError> {
        if self.is_closed() || !self.try_mark_active() {
            return Err(DispatchError::Other(
                "AnyTLS idle session is unavailable".to_owned(),
            ));
        }
        let stream_id =
            match self
                .next_stream_id
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                }) {
                Ok(previous) => previous + 1,
                Err(_) => {
                    self.fail(io::Error::other("AnyTLS stream ID exhausted"));
                    return Err(DispatchError::Other(
                        "AnyTLS stream ID exhausted".to_owned(),
                    ));
                }
            };
        let (active, receiver, shared, syn_ack) =
            make_active_stream(stream_id, self.incoming_capacity);
        {
            let mut slot = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.is_some() {
                drop(slot);
                self.fail(protocol_error("AnyTLS session retained an active stream"));
                return Err(DispatchError::Other(
                    "AnyTLS session retained an active stream".to_owned(),
                ));
            }
            *slot = Some(active);
        }
        let mut open_guard = ReusedOpenGuard::new(self.clone());
        let batch = open_stream_batch(stream_id, target).map_err(DispatchError::from)?;
        let (done, completion) = oneshot::channel();
        let writer = self.writer.clone();
        if let Err(error) = context
            .run_io("AnyTLS session open", async move {
                writer
                    .send(WriterCommand::Open {
                        stream_id,
                        batch,
                        done,
                    })
                    .await
                    .map_err(|_| closed_pipe("AnyTLS writer stopped"))?;
                completion
                    .await
                    .map_err(|_| closed_pipe("AnyTLS writer stopped"))?
            })
            .await
        {
            self.fail(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                error.to_string(),
            ));
            return Err(error);
        }

        if self.peer_version.load(Ordering::Acquire) >= 2 {
            let session = self.clone();
            tracker.spawn(crate::resources::observation::task(async move {
                let result = tokio::select! {
                    biased;
                    () = session.cancellation.cancelled() => return,
                    acknowledgement = tokio::time::timeout(SYN_ACK_TIMEOUT, syn_ack) => {
                        match acknowledgement {
                            Ok(Ok(result)) => result,
                            Ok(Err(_)) => Err(closed_pipe("AnyTLS SYNACK waiter stopped")),
                            Err(_) => Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "AnyTLS SYNACK timed out",
                            )),
                        }
                    }
                };
                if let Err(error) = result {
                    session.fail(error);
                }
            }));
        }

        open_guard.commit();
        Ok(AnyTlsStream::new(
            self.clone(),
            stream_id,
            receiver,
            shared,
            self.max_stream_chunk,
        ))
    }

    pub(crate) fn abandon_stream(self: &Arc<Self>, stream_id: u32) {
        let matches = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|active| active.stream_id == stream_id);
        if matches {
            self.fail(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS stream was dropped before FIN could be queued",
            ));
        }
    }

    pub(crate) fn begin_shutdown(self: &Arc<Self>) {
        self.fail(io::Error::new(
            io::ErrorKind::Interrupted,
            "AnyTLS client is shutting down",
        ));
    }

    fn next_packet(&self) -> u32 {
        self.packet_counter.fetch_add(1, Ordering::AcqRel)
    }

    fn release_stream(self: &Arc<Self>, stream_id: u32) -> io::Result<()> {
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(active) = active else {
            return Err(protocol_error("AnyTLS stream was already released"));
        };
        if active.stream_id != stream_id {
            self.fail(protocol_error("AnyTLS stream release ID mismatch"));
            return Err(protocol_error("AnyTLS stream release ID mismatch"));
        }
        active.shared.mark_local_finished();
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if self
            .state
            .compare_exchange(
                STATE_ACTIVE,
                STATE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.fail(protocol_error(
                "AnyTLS session state did not permit release",
            ));
            return Err(protocol_error(
                "AnyTLS session state did not permit release",
            ));
        }
        if let Some(client) = self.client.upgrade() {
            client.return_idle(self);
        } else {
            self.fail(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS client no longer exists",
            ));
        }
        Ok(())
    }

    fn fail(self: &Arc<Self>, error: io::Error) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.state.store(STATE_CLOSED, Ordering::Release);
        self.cancellation.cancel();
        let failure = StreamFailure::from_io(&error);
        if let Some(mut active) = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            active.shared.fail(failure.clone());
            if let Some(syn_ack) = active.syn_ack.take() {
                let _ = syn_ack.send(Err(io::Error::new(
                    error.kind(),
                    bounded_message(&error.to_string()),
                )));
            }
            let _ = active.incoming.try_send(StreamEvent::Failed(failure));
        }
        if let Some(client) = self.client.upgrade() {
            client.session_closed(self.sequence);
        }
    }
}

async fn writer_loop<W>(
    session: Arc<Session>,
    mut writer: W,
    mut commands: mpsc::Receiver<WriterCommand>,
) where
    W: AsyncWrite + Unpin,
{
    let result = loop {
        let command = tokio::select! {
            biased;
            () = session.cancellation.cancelled() => break Ok(()),
            command = commands.recv() => {
                let Some(command) = command else {
                    break Err(closed_pipe("AnyTLS writer command channel closed"));
                };
                command
            }
        };
        let operation = async {
            match command {
                WriterCommand::Open {
                    stream_id,
                    batch,
                    done,
                } => {
                    let result = write_packet(
                        &mut writer,
                        &session.padding_snapshot,
                        session.next_packet(),
                        &batch,
                    )
                    .await;
                    let returned = clone_io_result(&result);
                    let _ = done.send(returned);
                    result.map(|()| {
                        debug_assert!(stream_id > 1);
                    })
                }
                WriterCommand::Data {
                    stream_id,
                    payload,
                    done,
                } => {
                    let result = if active_matches(&session, stream_id) {
                        let frame = Frame::with_payload(Command::Push, stream_id, payload)
                            .and_then(|frame| encode_batch(&[frame]));
                        match frame {
                            Ok(frame) => {
                                write_packet(
                                    &mut writer,
                                    &session.padding_snapshot,
                                    session.next_packet(),
                                    &frame,
                                )
                                .await
                            }
                            Err(error) => Err(error),
                        }
                    } else {
                        Err(protocol_error("AnyTLS write targets an inactive stream"))
                    };
                    let _ = done.send(clone_io_result(&result));
                    result
                }
                WriterCommand::Flush { done } => {
                    let result = writer.flush().await;
                    let _ = done.send(clone_io_result(&result));
                    result
                }
                WriterCommand::CloseStream {
                    stream_id,
                    send_fin,
                    done,
                } => {
                    let result = if send_fin {
                        let frame = encode_batch(&[Frame::empty(Command::Fin, stream_id)]);
                        match frame {
                            Ok(frame) => {
                                write_packet(
                                    &mut writer,
                                    &session.padding_snapshot,
                                    session.next_packet(),
                                    &frame,
                                )
                                .await
                            }
                            Err(error) => Err(error),
                        }
                    } else {
                        Ok(())
                    };
                    let result = result.and_then(|()| session.release_stream(stream_id));
                    if let Some(done) = done {
                        let _ = done.send(clone_io_result(&result));
                    }
                    result
                }
                WriterCommand::Control(frame) => {
                    let frame = encode_batch(&[frame]);
                    match frame {
                        Ok(frame) => {
                            write_packet(
                                &mut writer,
                                &session.padding_snapshot,
                                session.next_packet(),
                                &frame,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    }
                }
            }
        };
        let result = tokio::select! {
            biased;
            () = session.cancellation.cancelled() => break Ok(()),
            result = operation => result,
        };
        if let Err(error) = result {
            break Err(error);
        }
    };
    if let Err(error) = result {
        session.fail(error);
    }
}

async fn reader_loop<R>(session: Arc<Session>, mut reader: R)
where
    R: AsyncRead + Unpin,
{
    let result = loop {
        let frame = tokio::select! {
            biased;
            () = session.cancellation.cancelled() => break Ok(()),
            frame = read_frame(&mut reader) => match frame {
                Ok(frame) => frame,
                Err(error) => break Err(error),
            },
        };
        if let Err(error) = handle_server_frame(&session, frame).await {
            break Err(error);
        }
    };
    if let Err(error) = result {
        session.fail(error);
    }
}

async fn handle_server_frame(session: &Arc<Session>, frame: Frame) -> io::Result<()> {
    match frame.command {
        Command::Waste => {
            require_control_stream(&frame, "AnyTLS Waste uses a non-zero stream ID")?;
            Ok(())
        }
        Command::Push => {
            if frame.stream_id == 0 {
                return Err(protocol_error("AnyTLS PSH uses stream ID zero"));
            }
            let Some((incoming, shared)) = active_target(session, frame.stream_id)? else {
                return Ok(());
            };
            if shared.remote_finished() {
                return Err(protocol_error("AnyTLS PSH arrived after stream FIN"));
            }
            let local_cancellation = shared.local_cancellation();
            let mut offset = 0;
            while offset < frame.payload.len() {
                let end = (offset + session.max_stream_chunk).min(frame.payload.len());
                let event = StreamEvent::Data(frame.payload.slice(offset..end));
                tokio::select! {
                    biased;
                    () = session.cancellation.cancelled() => {
                        return Err(closed_pipe("AnyTLS session stopped"));
                    }
                    () = local_cancellation.cancelled() => return Ok(()),
                    result = incoming.send(event) => {
                        result.map_err(|_| closed_pipe("AnyTLS stream receiver stopped"))?;
                    }
                }
                offset = end;
            }
            Ok(())
        }
        Command::Fin => {
            require_empty(&frame, "FIN")?;
            let Some((incoming, shared)) = active_target(session, frame.stream_id)? else {
                return Ok(());
            };
            shared.mark_remote_finished();
            let local_cancellation = shared.local_cancellation();
            tokio::select! {
                biased;
                () = session.cancellation.cancelled() => {
                    return Err(closed_pipe("AnyTLS session stopped"));
                }
                () = local_cancellation.cancelled() => {}
                result = incoming.send(StreamEvent::Finished) => {
                    let _ = result;
                }
            }
            Ok(())
        }
        Command::SynAck => handle_syn_ack(session, frame),
        Command::Alert => {
            if frame.stream_id != 0 {
                return Err(protocol_error("AnyTLS Alert uses a non-zero stream ID"));
            }
            tracing::warn!("AnyTLS server alert");
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS server alert",
            ))
        }
        Command::UpdatePaddingScheme => {
            if frame.stream_id != 0 || frame.payload.is_empty() {
                return Err(protocol_error(
                    "AnyTLS padding update has an invalid header",
                ));
            }
            match PaddingScheme::parse(&frame.payload) {
                Ok(padding) => session.client_padding.store(Arc::new(padding)),
                Err(error) => {
                    tracing::warn!(error = %error, "ignored invalid AnyTLS padding update");
                }
            }
            Ok(())
        }
        Command::HeartRequest => {
            require_control_stream(&frame, "AnyTLS heartbeat request uses a non-zero stream ID")?;
            require_empty(&frame, "heartbeat request")?;
            tokio::select! {
                biased;
                () = session.cancellation.cancelled() => {
                    Err(closed_pipe("AnyTLS session stopped"))
                }
                result = session.writer.send(WriterCommand::Control(Frame::empty(
                    Command::HeartResponse,
                    frame.stream_id,
                ))) => {
                    result.map_err(|_| closed_pipe("AnyTLS writer stopped"))
                }
            }
        }
        Command::HeartResponse => {
            require_control_stream(
                &frame,
                "AnyTLS heartbeat response uses a non-zero stream ID",
            )?;
            require_empty(&frame, "heartbeat response")?;
            Ok(())
        }
        Command::ServerSettings => {
            if frame.stream_id != 0 || frame.payload.is_empty() {
                return Err(protocol_error(
                    "AnyTLS server settings have an invalid header",
                ));
            }
            let version = parse_server_version(&frame.payload)?;
            session
                .peer_version
                .fetch_max(version.min(2), Ordering::AcqRel);
            Ok(())
        }
        Command::Syn | Command::Settings => Err(protocol_error(
            "AnyTLS server sent a client-only frame command",
        )),
    }
}

fn handle_syn_ack(session: &Arc<Session>, frame: Frame) -> io::Result<()> {
    if frame.stream_id == 0 {
        return Err(protocol_error("AnyTLS SYNACK uses stream ID zero"));
    }
    let mut active = session
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(active) = active.as_mut() else {
        return if is_allocated_stream(session, frame.stream_id) {
            Ok(())
        } else {
            Err(protocol_error("AnyTLS SYNACK targets an unknown stream"))
        };
    };
    if active.stream_id != frame.stream_id {
        if frame.stream_id < active.stream_id {
            return Ok(());
        }
        return Err(protocol_error("AnyTLS SYNACK targets an unknown stream"));
    }
    if frame.payload.is_empty() {
        if let Some(waiter) = active.syn_ack.take() {
            let _ = waiter.send(Ok(()));
        }
        return Ok(());
    }

    let message = "AnyTLS stream rejected by server";
    let failure = StreamFailure::new(io::ErrorKind::ConnectionRefused, Arc::<str>::from(message));
    active.shared.fail(failure.clone());
    let _ = active.incoming.try_send(StreamEvent::Failed(failure));
    if let Some(waiter) = active.syn_ack.take() {
        let _ = waiter.send(Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            message,
        )));
    }
    Err(io::Error::new(io::ErrorKind::ConnectionRefused, message))
}

fn active_target(
    session: &Session,
    stream_id: u32,
) -> io::Result<Option<(mpsc::Sender<StreamEvent>, Arc<StreamShared>)>> {
    if stream_id == 0 {
        return Err(protocol_error("AnyTLS data frame uses stream ID zero"));
    }
    let active = session
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(active) = active.as_ref() else {
        return if is_allocated_stream(session, stream_id) {
            Ok(None)
        } else {
            Err(protocol_error("AnyTLS frame targets an unknown stream"))
        };
    };
    if active.stream_id == stream_id {
        return Ok(Some((active.incoming.clone(), active.shared.clone())));
    }
    if stream_id < active.stream_id {
        return Ok(None);
    }
    Err(protocol_error("AnyTLS frame targets a future stream"))
}

fn is_allocated_stream(session: &Session, stream_id: u32) -> bool {
    stream_id != 0 && stream_id <= session.next_stream_id.load(Ordering::Acquire)
}

fn active_matches(session: &Session, stream_id: u32) -> bool {
    session
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_some_and(|active| active.stream_id == stream_id)
}

fn make_active_stream(
    stream_id: u32,
    capacity: usize,
) -> (
    ActiveStream,
    mpsc::Receiver<StreamEvent>,
    Arc<StreamShared>,
    oneshot::Receiver<io::Result<()>>,
) {
    let (incoming, receiver) = mpsc::channel(capacity.max(1));
    let shared = StreamShared::new();
    let (syn_ack, acknowledgement) = oneshot::channel();
    (
        ActiveStream {
            stream_id,
            incoming,
            shared: shared.clone(),
            syn_ack: Some(syn_ack),
        },
        receiver,
        shared,
        acknowledgement,
    )
}

fn first_stream_batch(
    padding: &PaddingScheme,
    target: &Destination,
    client_metadata: &str,
) -> io::Result<Bytes> {
    let settings = format!(
        "v=2\nclient={client_metadata}\npadding-md5={}",
        padding.md5_hex()
    );
    let target = encoded_target(target)?;
    encode_batch(&[
        Frame::with_payload(Command::Settings, 0, Bytes::from(settings))?,
        Frame::empty(Command::Syn, 1),
        Frame::with_payload(Command::Push, 1, target)?,
    ])
}

fn open_stream_batch(stream_id: u32, target: &Destination) -> io::Result<Bytes> {
    encode_batch(&[
        Frame::empty(Command::Syn, stream_id),
        Frame::with_payload(Command::Push, stream_id, encoded_target(target)?)?,
    ])
}

fn encoded_target(target: &Destination) -> io::Result<Bytes> {
    let mut encoded = Vec::with_capacity(259);
    encode_address(target, &mut encoded)?;
    Ok(Bytes::from(encoded))
}

fn parse_server_version(payload: &[u8]) -> io::Result<u8> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| protocol_error("AnyTLS server settings are not UTF-8"))?;
    let mut version = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| protocol_error("AnyTLS server setting has no equals sign"))?;
        if key == "v" {
            if version.is_some() {
                return Err(protocol_error("AnyTLS server repeats its version"));
            }
            version = Some(
                value
                    .parse::<u8>()
                    .map_err(|_| protocol_error("AnyTLS server version is invalid"))?,
            );
        }
    }
    version
        .filter(|version| *version > 0)
        .ok_or_else(|| protocol_error("AnyTLS server settings omit a valid version"))
}

fn require_empty(frame: &Frame, name: &'static str) -> io::Result<()> {
    if frame.payload.is_empty() {
        Ok(())
    } else {
        Err(protocol_error(match name {
            "FIN" => "AnyTLS FIN unexpectedly carries data",
            "heartbeat request" => "AnyTLS heartbeat request unexpectedly carries data",
            "heartbeat response" => "AnyTLS heartbeat response unexpectedly carries data",
            _ => "AnyTLS control frame unexpectedly carries data",
        }))
    }
}

fn require_control_stream(frame: &Frame, message: &'static str) -> io::Result<()> {
    if frame.stream_id == 0 {
        Ok(())
    } else {
        Err(protocol_error(message))
    }
}

fn clone_io_result(result: &io::Result<()>) -> io::Result<()> {
    result
        .as_ref()
        .copied()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

fn bounded_message(message: &str) -> String {
    if message.len() <= MAX_DIAGNOSTIC_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES - 3;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &message[..end])
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn closed_pipe(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn remote_alerts_and_synack_errors_never_echo_peer_payloads() {
        use tokio::io::AsyncReadExt;
        for (command, stream_id, expected, kind) in [
            (
                Command::Alert,
                0,
                "AnyTLS server alert",
                io::ErrorKind::ConnectionAborted,
            ),
            (
                Command::SynAck,
                1,
                "AnyTLS stream rejected by server",
                io::ErrorKind::ConnectionRefused,
            ),
        ] {
            let padding = Arc::new(PaddingScheme::default_scheme());
            let (raw, _peer) = tokio::io::duplex(65536);
            let mut prepared = Session::prepare_first(
                1,
                Weak::new(),
                Box::new(raw),
                [0; 32],
                padding.clone(),
                Arc::new(ArcSwap::new(padding)),
                &Destination::domain("target.example", 443).unwrap(),
                "",
                1024,
                1,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
            let session = prepared.session();
            let payload =
                Bytes::from_static(b"synthetic-secret target.private.invalid\r\nforged-log");
            let error = handle_server_frame(
                &session,
                Frame::with_payload(command, stream_id, payload).unwrap(),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), expected);
            session.fail(error);
            let propagated = prepared.stream.read(&mut [0]).await.unwrap_err();
            assert_eq!(propagated.to_string(), expected);
        }
    }

    #[test]
    fn server_settings_version_is_strict_and_bounded_to_supported_v2() {
        assert_eq!(parse_server_version(b"v=1").unwrap(), 1);
        assert_eq!(parse_server_version(b"server=test\nv=2").unwrap(), 2);
        assert_eq!(parse_server_version(b"v=255").unwrap().min(2), 2);
        assert!(parse_server_version(b"v=0").is_err());
        assert!(parse_server_version(b"v=2\nv=1").is_err());
        assert!(parse_server_version(b"server=test").is_err());
        assert!(parse_server_version(&[0xff]).is_err());
    }

    #[test]
    fn strict_control_frames_use_stream_zero() {
        assert!(
            require_control_stream(&Frame::empty(Command::Waste, 0), "invalid control stream",)
                .is_ok()
        );
        assert!(
            require_control_stream(
                &Frame::empty(Command::HeartRequest, 1),
                "invalid control stream",
            )
            .is_err()
        );
        assert!(
            require_control_stream(
                &Frame::empty(Command::HeartResponse, u32::MAX),
                "invalid control stream",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn initial_batches_keep_settings_before_stream_open_and_target() {
        let target = Destination::domain("target.example", 443).unwrap();
        let padding = PaddingScheme::default_scheme();
        let batch = first_stream_batch(&padding, &target, "test=metadata").unwrap();
        let mut input = std::io::Cursor::new(batch);
        let settings = read_frame(&mut input).await.unwrap();
        let syn = read_frame(&mut input).await.unwrap();
        let target_frame = read_frame(&mut input).await.unwrap();
        assert_eq!(settings.command, Command::Settings);
        assert_eq!(settings.stream_id, 0);
        assert_eq!(
            settings.payload.as_ref(),
            format!(
                "v=2\nclient=test=metadata\npadding-md5={}",
                padding.md5_hex()
            )
            .as_bytes()
        );
        assert_eq!(syn, Frame::empty(Command::Syn, 1));
        assert_eq!(target_frame.command, Command::Push);
        assert_eq!(target_frame.stream_id, 1);
        assert!(!target_frame.payload.is_empty());
    }
}
