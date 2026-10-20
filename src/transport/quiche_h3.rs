//! Official quiche HTTP/3 over the shared protected datagram adapter.
//!
//! One owner drives QUIC and HTTP/3. Application handles use short synchronous
//! locks; they never own a socket, resolver, native worker, or event channel.
use crate::{
    dispatch::{DatagramBudget, DatagramTransport},
    security::QuicheTls,
    transport::quic,
};
use bytes::{Buf, Bytes};
use futures_util::{future::poll_fn, task::AtomicWaker};
use http::{Request, Response};
use quiche::h3::NameValue;
use quinn::AsyncUdpSocket;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub(crate) const REQUEST_CANCELLED: u64 = 0x10c;
const CHUNK: usize = crate::transport::STREAM_CHUNK_BYTES;
const BODY_LIMIT: usize = crate::transport::STREAM_BUFFER_BYTES;
const DATAGRAM_QUEUE: usize = 64;
const WORK: usize = 32;
const RECEIVE_BATCH: usize = 16;

#[derive(Clone, Debug, Default)]
struct OwnedBuffers;
impl quiche::BufFactory for OwnedBuffers {
    type Buf = Bytes;
    type DgramBuf = Bytes;

    fn buf_from_slice(input: &[u8]) -> Bytes {
        Bytes::copy_from_slice(input)
    }

    fn dgram_buf_from_slice(input: &[u8]) -> Bytes {
        Bytes::copy_from_slice(input)
    }
}
type NativeConnection = quiche::Connection<OwnedBuffers>;

/// Protocol token for a locally admitted extended CONNECT request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Protocol(pub &'static str);
impl Protocol {
    pub const CF_CONNECT_IP: Self = Self("cf-connect-ip");
}

pub(crate) struct Transport {
    pub transport: Box<dyn DatagramTransport>,
    pub peer: SocketAddr,
    pub budget: DatagramBudget,
    pub tls: QuicheTls,
    pub server_name: String,
}
#[derive(Clone, Copy)]
pub(crate) struct Options {
    pub stream_window: u64,
    pub connection_window: u64,
    pub idle: Duration,
    pub keepalive: Option<Duration>,
    pub datagrams: bool,
    pub headers: u64,
    pub congestion: quiche::CongestionControlAlgorithm,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            stream_window: 128 * 1024,
            connection_window: 256 * 1024,
            idle: Duration::from_secs(74),
            keepalive: None,
            datagrams: false,
            headers: CHUNK as u64,
            congestion: quiche::CongestionControlAlgorithm::CUBIC,
        }
    }
}
#[derive(Default)]
struct Signals {
    read: AtomicWaker,
    write: AtomicWaker,
    datagram: AtomicWaker,
}
struct Body {
    signals: Arc<Signals>,
    headers: Option<Response<()>>,
    headers_received: bool,
    trailers_received: bool,
    data: VecDeque<Bytes>,
    buffered: usize,
    readable: bool,
    finished: bool,
    failed: bool,
    receive_owned: bool,
    send_owned: bool,
    send_finished: bool,
    datagrams: Option<VecDeque<Bytes>>,
}
impl Body {
    fn new(signals: Arc<Signals>) -> Self {
        Self {
            signals,
            headers: None,
            headers_received: false,
            trailers_received: false,
            data: VecDeque::new(),
            buffered: 0,
            readable: false,
            finished: false,
            failed: false,
            receive_owned: true,
            send_owned: true,
            send_finished: false,
            datagrams: None,
        }
    }
    fn wake(&self) {
        self.signals.read.wake();
        self.signals.write.wake();
        self.signals.datagram.wake();
    }
}
struct State {
    connection: Option<NativeConnection>,
    h3: Option<quiche::h3::Connection>,
    streams: BTreeMap<u64, Body>,
    closed: bool,
    goaway: bool,
    ready: bool,
    datagram_budget: Option<usize>,
    settings: Option<Vec<(u64, u64)>>,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
    status: Notify,
}
impl Shared {
    fn finish(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        for body in state.streams.values_mut() {
            body.failed = true;
            body.data.clear();
            body.buffered = 0;
            body.wake();
        }
        state.streams.clear();
        state.h3.take();
        state.connection.take();
        state.datagram_budget = None;
        drop(state);
        self.status.notify_waiters();
        self.changed.notify_one();
    }
}
#[derive(Clone)]
pub(crate) struct Client {
    shared: Arc<Shared>,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3Client").finish_non_exhaustive()
    }
}
pub(crate) struct Driver {
    shared: Arc<Shared>,
    socket: Arc<quic::DatagramSocket>,
    datagram: Option<quic::DatagramDriver>,
    tls: QuicheTls,
    options: Options,
    peer: SocketAddr,
    local: SocketAddr,
    mtu: usize,
}
impl Driver {
    pub(crate) async fn new(mut raw: Transport, options: Options) -> io::Result<(Client, Self)> {
        let prepared = (|| {
            if raw.server_name != raw.tls.server_name()
                || raw.peer.port() == 0
                || raw.peer.ip().is_unspecified()
                || raw.peer.ip().is_multicast()
            {
                return Err(invalid());
            }
            let budget = raw.budget.intersect(
                raw.transport
                    .payload_budget(&crate::session::Destination::Ip(raw.peer)),
            );
            let mtu = budget.quic_payload_limit()? as usize;
            let local = if raw.peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();
            let mut config = raw.tls.build_config()?;
            config
                .set_max_idle_timeout(options.idle.as_millis().try_into().map_err(|_| invalid())?);
            config.set_max_recv_udp_payload_size(budget.receive() as usize);
            config.set_max_send_udp_payload_size(mtu);
            config.discover_pmtu(true);
            config.set_initial_max_data(options.connection_window);
            config.set_initial_max_stream_data_bidi_local(options.stream_window);
            config.set_initial_max_stream_data_bidi_remote(options.stream_window);
            config.set_initial_max_stream_data_uni(CHUNK as u64);
            config.set_initial_max_streams_bidi(0);
            config.set_initial_max_streams_uni(8);
            config.set_max_connection_window(options.connection_window);
            config.set_max_stream_window(options.stream_window);
            config.set_cc_algorithm(options.congestion);
            config.enable_dgram(options.datagrams, DATAGRAM_QUEUE, DATAGRAM_QUEUE);
            let mut cid = [0_u8; 20];
            boring::rand::rand_bytes(&mut cid).map_err(failure)?;
            let mut connection = quiche::connect_with_buffer_factory::<OwnedBuffers>(
                Some(raw.tls.server_name()),
                &quiche::ConnectionId::from_ref(&cid),
                local,
                raw.peer,
                &mut config,
            )
            .map_err(failure)?;
            raw.tls.prepare_connection(&mut connection)?;
            Ok::<_, io::Error>((connection, budget, local, mtu))
        })();
        let (connection, budget, local, mtu) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, raw.transport.close()).await;
                return Err(error);
            }
        };
        let (socket, datagram) = quic::attach(raw.transport, raw.peer, budget)?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                connection: Some(connection),
                h3: None,
                streams: BTreeMap::new(),
                closed: false,
                goaway: false,
                ready: false,
                datagram_budget: None,
                settings: None,
            }),
            changed: Notify::new(),
            status: Notify::new(),
        });
        Ok((
            Client {
                shared: shared.clone(),
            },
            Self {
                shared,
                socket,
                datagram: Some(datagram),
                tls: raw.tls,
                options,
                peer: raw.peer,
                local,
                mtu,
            },
        ))
    }
    /// This future owns the adapter until its close and join have completed.
    pub(crate) async fn run(mut self, cancel: CancellationToken) -> io::Result<()> {
        let result = self.drive(&cancel).await;
        self.shared.finish();
        if let Some(datagram) = self.datagram.take() {
            let closed = datagram.stop().await;
            return result.and(closed);
        }
        result
    }
    async fn drive(&mut self, cancel: &CancellationToken) -> io::Result<()> {
        // Shared/static upstream packets retain the original bounded scratch
        // fallback. Unique packets can be decrypted in their owned storage.
        let mut incoming = Vec::new();
        let mut output = vec![0; self.mtu];
        let mut pending: Option<(usize, std::time::Instant)> = None;
        let mut writable = self.socket.clone().create_io_poller();
        let mut closing = None;
        let mut close_sent = false;
        let mut queued = 0;
        let mut transmitted = 0;
        let mut quiet_until = None;
        let mut keepalive = self
            .options
            .keepalive
            .map(|delay| tokio::time::Instant::now() + delay);
        loop {
            if cancel.is_cancelled() && closing.is_none() {
                closing = Some(tokio::time::Instant::now() + quic::CLOSE_TIMEOUT);
                let mut state = self.shared.state.lock().unwrap();
                // Retire admission immediately. Existing halves may still
                // receive ACKs and send already accepted upload data below.
                state.goaway = true;
                self.shared.status.notify_waiters();
                quiet_until = Some(
                    tokio::time::Instant::now() + retire_grace(state.connection.as_ref().unwrap()),
                );
            }
            let notify = self.shared.changed.notified();
            {
                let mut state = self.shared.state.lock().unwrap();
                if state
                    .connection
                    .as_mut()
                    .unwrap()
                    .timeout()
                    .is_some_and(|delay| delay.is_zero())
                {
                    state.connection.as_mut().unwrap().on_timeout();
                }
                if state.connection.as_mut().unwrap().is_closed()
                    || closing.is_some_and(|at| tokio::time::Instant::now() >= at)
                {
                    break;
                }
                if state.connection.as_mut().unwrap().is_established() && !state.ready {
                    self.tls
                        .check_handshake(state.connection.as_mut().unwrap())?;
                    let mut options = quiche::h3::Config::new().map_err(failure)?;
                    options.set_max_field_section_size(self.options.headers);
                    options.enable_extended_connect(true);
                    state.h3 = Some(
                        quiche::h3::Connection::with_transport(
                            state.connection.as_mut().unwrap(),
                            &options,
                        )
                        .map_err(failure)?,
                    );
                    state.ready = true;
                    self.shared.status.notify_waiters();
                }
                process_h3(&mut state)?;
                state.datagram_budget = state.connection.as_mut().unwrap().dgram_max_writable_len();
                if closing.is_none()
                    && keepalive.is_some_and(|at| tokio::time::Instant::now() >= at)
                {
                    let _ = state.connection.as_mut().unwrap().send_ack_eliciting();
                    keepalive = self
                        .options
                        .keepalive
                        .map(|delay| tokio::time::Instant::now() + delay);
                }
                // Wakes application backpressure after ACK/credit processing.
                for body in state.streams.values() {
                    body.signals.write.wake();
                }
                self.shared.status.notify_waiters();
            }
            let mut native_idle = false;
            let mut timeout = {
                let mut sending = self.shared.state.lock().unwrap();
                for _ in 0..WORK {
                    if pending.is_none() {
                        let sent = sending.connection.as_mut().unwrap().send(&mut output);
                        match sent {
                            Ok((n, info)) if info.to == self.peer => pending = Some((n, info.at)),
                            Ok(_) => return Err(invalid()),
                            Err(quiche::Error::Done) => {
                                native_idle = true;
                                break;
                            }
                            Err(error) => return Err(failure(error)),
                        }
                    }
                    let (n, at) = pending.unwrap();
                    if at > std::time::Instant::now() {
                        break;
                    }
                    match self.socket.try_send(&quinn::udp::Transmit {
                        destination: self.peer,
                        ecn: None,
                        contents: &output[..n],
                        segment_size: None,
                        src_ip: None,
                    }) {
                        Ok(()) => {
                            pending = None;
                            queued += 1;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
                // Native send arms recovery timers, including an isolated PTO.
                sending
                    .connection
                    .as_ref()
                    .unwrap()
                    .timeout()
                    .map(|delay| tokio::time::Instant::now() + delay)
            };
            let sent = self.socket.stats().sent;
            if sent != transmitted {
                transmitted = sent;
                if closing.is_some() && !close_sent {
                    let state = self.shared.state.lock().unwrap();
                    quiet_until = Some(
                        tokio::time::Instant::now()
                            + retire_grace(state.connection.as_ref().unwrap()),
                    );
                }
            }
            if closing.is_some()
                && !close_sent
                && native_idle
                && pending.is_none()
                && transmitted >= queued
                && quiet_until.is_some_and(|at| tokio::time::Instant::now() >= at)
            {
                // FIN acceptance is not an ACK barrier. Give native queues and
                // the controlled transport bounded continued IO before close
                // can preempt them; never extend the original close deadline.
                let mut state = self.shared.state.lock().unwrap();
                let connection = state.connection.as_mut().unwrap();
                let _ = connection.close(true, 0x100, b"");
                // Close may replace the timer sampled after the send loop.
                timeout = connection
                    .timeout()
                    .map(|delay| tokio::time::Instant::now() + delay);
                close_sent = true;
                drop(state);
                self.shared.changed.notify_one();
            }
            let deadline = timeout
                .into_iter()
                .chain(closing)
                .chain(keepalive.filter(|_| closing.is_none()))
                .chain(quiet_until.filter(|_| {
                    closing.is_some() && !close_sent && pending.is_none() && transmitted >= queued
                }))
                .chain(
                    pending
                        .filter(|(_, at)| *at > std::time::Instant::now())
                        .map(|(_, at)| tokio::time::Instant::from_std(at)),
                )
                .min();
            let recv = poll_fn(|cx| {
                let mut state = self.shared.state.lock().unwrap();
                let connection = state.connection.as_mut().unwrap();
                let mut received = false;
                // Decode one ready burst before delivering H3 bodies and
                // waking writers. Never wait for a batch to fill or retain
                // additional packet buffers, and bound owner work per poll.
                for _ in 0..RECEIVE_BATCH {
                    match self.socket.poll_recv_owned(cx) {
                        Poll::Ready(Ok(payload)) => {
                            let info = quiche::RecvInfo {
                                from: self.peer,
                                to: self.local,
                            };
                            let result = match payload.try_into_mut() {
                                Ok(mut payload) => connection.recv(&mut payload, info),
                                Err(payload) => {
                                    if incoming.is_empty() {
                                        incoming.resize(self.socket.budget().receive() as usize, 0);
                                    }
                                    incoming[..payload.len()].copy_from_slice(&payload);
                                    connection.recv(&mut incoming[..payload.len()], info)
                                }
                            };
                            match result {
                                Ok(_) | Err(quiche::Error::Done) => {}
                                Err(error) => return Poll::Ready(Err(failure(error))),
                            }
                            received = true;
                            // Deliver DATAGRAMs before another packet can
                            // overflow their bounded native receive queue.
                            if connection.dgram_recv_queue_len() != 0 {
                                break;
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => break,
                    }
                }
                if received {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            });
            tokio::select! {
                biased;
                () = cancel.cancelled(), if closing.is_none() => {},
                received = recv => { received?; },
                () = notify => {},
                result = poll_fn(|cx| self.socket.poll_transmitted(cx, queued)), if closing.is_some() && !close_sent && pending.is_none() && transmitted < queued => { result?; },
                result = poll_fn(|cx| writable.as_mut().poll_writable(cx)), if pending.is_some_and(|(_, at)| at <= std::time::Instant::now()) => { result?; },
                () = async { match deadline { Some(at) => tokio::time::sleep_until(at).await, None => std::future::pending().await } } => {
                    let mut state = self.shared.state.lock().unwrap();
                    if state.connection.as_mut().unwrap().timeout().is_some_and(|delay| delay.is_zero()) { state.connection.as_mut().unwrap().on_timeout(); }
                },
            }
        }
        Ok(())
    }
}
// A retirement grace follows real transport progress and measured RTT. It is
// only an opportunity to deliver queued data, never proof of remote receipt.
fn retire_grace(connection: &NativeConnection) -> Duration {
    connection
        .path_stats()
        .filter(|path| path.active)
        .map(|path| path.rtt)
        .max()
        .unwrap_or(Duration::ZERO)
        .saturating_mul(2)
        .saturating_add(Duration::from_millis(25))
        .min(quic::CLOSE_TIMEOUT)
}
fn process_h3(state: &mut State) -> io::Result<()> {
    let Some(h3) = state.h3.as_mut() else {
        return Ok(());
    };
    for _ in 0..WORK {
        match h3.poll(state.connection.as_mut().unwrap()) {
            Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                let Some(body) = state.streams.get_mut(&id) else {
                    let _ = state.connection.as_mut().unwrap().stream_shutdown(
                        id,
                        quiche::Shutdown::Read,
                        REQUEST_CANCELLED,
                    );
                    continue;
                };
                let (status, headers) = parse_headers(list)?;
                if let Some(status) = status {
                    if status.is_informational() {
                        continue;
                    }
                    if body.headers_received {
                        body.failed = true;
                    } else {
                        body.headers_received = true;
                        let mut response = Response::new(());
                        *response.status_mut() = status;
                        *response.version_mut() = http::Version::HTTP_3;
                        *response.headers_mut() = headers;
                        body.headers = Some(response);
                    }
                } else if body.headers_received && !body.trailers_received {
                    body.trailers_received = true;
                } else {
                    body.failed = true;
                }
                body.signals.read.wake();
            }
            Ok((id, quiche::h3::Event::Data)) => {
                if let Some(body) = state.streams.get_mut(&id) {
                    body.readable = true;
                }
            }
            Ok((id, quiche::h3::Event::Finished)) => {
                if let Some(body) = state.streams.get_mut(&id) {
                    body.finished = true;
                    body.signals.read.wake();
                }
            }
            Ok((id, quiche::h3::Event::Reset(_))) => {
                if let Some(body) = state.streams.get_mut(&id) {
                    body.failed = true;
                    body.wake();
                }
            }
            Ok((_, quiche::h3::Event::GoAway)) => {
                state.goaway = true;
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(error) => return Err(failure(error)),
        }
    }
    if state.settings.is_none() {
        state.settings = h3.peer_settings_raw().map(|settings| settings.to_vec());
    }
    let mut buf = [0; CHUNK];
    for (&id, body) in &mut state.streams {
        for _ in 0..BODY_LIMIT / CHUNK {
            if !body.readable || body.buffered == BODY_LIMIT || !body.receive_owned {
                break;
            }
            let maximum = buf.len().min(BODY_LIMIT - body.buffered);
            match h3.recv_body(state.connection.as_mut().unwrap(), id, &mut buf[..maximum]) {
                Ok(n) => {
                    body.buffered += n;
                    body.data.push_back(Bytes::copy_from_slice(&buf[..n]));
                    body.signals.read.wake();
                }
                Err(quiche::h3::Error::Done) => {
                    body.readable = false;
                    break;
                }
                Err(_) => {
                    body.failed = true;
                    body.wake();
                    break;
                }
            }
        }
    }
    // Unknown flow identifiers never allocate a map entry or an event.
    for _ in 0..WORK {
        match state.connection.as_mut().unwrap().dgram_recv_buf() {
            Ok(frame) => {
                if frame.len() > CHUNK {
                    return Err(failure(quiche::Error::BufferTooShort));
                }
                let Some((flow, _)) = varint(&frame) else {
                    continue;
                };
                let Some(id) = flow.checked_mul(4) else {
                    continue;
                };
                let Some(queue) = state
                    .streams
                    .get_mut(&id)
                    .and_then(|body| body.datagrams.as_mut())
                else {
                    continue;
                };
                if queue.len() < DATAGRAM_QUEUE {
                    queue.push_back(frame);
                    state.streams[&id].signals.datagram.wake();
                }
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(failure(error)),
        }
    }
    Ok(())
}
fn parse_headers(
    list: Vec<quiche::h3::Header>,
) -> io::Result<(Option<http::StatusCode>, http::HeaderMap)> {
    let mut status = None;
    let mut headers = http::HeaderMap::new();
    let mut bytes = 0;
    for header in list {
        bytes += header.name().len() + header.value().len();
        if bytes > CHUNK {
            return Err(invalid());
        }
        if header.name() == b":status" {
            if status.is_some() {
                return Err(invalid());
            }
            status = Some(http::StatusCode::from_bytes(header.value()).map_err(|_| invalid())?);
        } else if header.name().starts_with(b":") {
            return Err(invalid());
        } else {
            headers.append(
                http::HeaderName::from_bytes(header.name()).map_err(|_| invalid())?,
                http::HeaderValue::from_bytes(header.value()).map_err(|_| invalid())?,
            );
        }
    }
    Ok((status, headers))
}
impl Client {
    pub(crate) async fn ready(&self, require_datagram_settings: bool) -> io::Result<()> {
        loop {
            let notified = self.shared.status.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.shared.state.lock().unwrap();
                if state.closed {
                    return Err(closed());
                }
                if state.ready {
                    if !require_datagram_settings {
                        return Ok(());
                    }
                    if let Some(settings) = state.settings.as_ref() {
                        return if settings.iter().any(|&(id, value)| id == 0x33 && value == 1) {
                            Ok(())
                        } else {
                            Err(invalid())
                        };
                    }
                }
            }
            notified.await;
        }
    }
    pub(crate) fn can_open_request(&self) -> bool {
        let state = self.shared.state.lock().unwrap();
        !state.closed && !state.goaway && state.ready
    }
    pub(crate) fn close_reason(&self) -> Option<()> {
        let state = self.shared.state.lock().unwrap();
        (state.closed
            || state
                .connection
                .as_ref()
                .is_none_or(NativeConnection::is_closed))
        .then_some(())
    }
    pub(crate) async fn send_request(&mut self, request: Request<()>) -> io::Result<RequestStream> {
        let headers = request_headers(&request)?;
        loop {
            let notified = self.shared.status.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.shared.state.lock().unwrap();
                if state.closed || state.goaway {
                    return Err(closed());
                }
                let State {
                    connection,
                    h3,
                    streams,
                    ..
                } = &mut *state;
                if let Some(h3) = h3.as_mut() {
                    match h3.send_request(connection.as_mut().unwrap(), &headers, false) {
                        Ok(id) => {
                            let signals = Arc::new(Signals::default());
                            streams.insert(id, Body::new(signals.clone()));
                            drop(state);
                            self.shared.changed.notify_one();
                            return Ok(RequestStream {
                                send: SendStream {
                                    client: self.clone(),
                                    id,
                                    signals: signals.clone(),
                                },
                                receive: RecvStream {
                                    client: self.clone(),
                                    id,
                                    signals,
                                },
                            });
                        }
                        Err(quiche::h3::Error::StreamBlocked)
                        | Err(quiche::h3::Error::TransportError(quiche::Error::StreamLimit)) => {}
                        Err(error) => return Err(failure(error)),
                    }
                }
            }
            notified.await;
        }
    }
    pub(crate) fn max_datagram_size(&self) -> Option<usize> {
        self.shared.state.lock().unwrap().datagram_budget
    }
    pub(crate) fn register_datagrams(&self, id: u64) -> io::Result<()> {
        self.shared
            .state
            .lock()
            .unwrap()
            .streams
            .get_mut(&id)
            .ok_or_else(closed)?
            .datagrams = Some(VecDeque::new());
        Ok(())
    }
    pub(crate) async fn send_datagram_wait(&self, frame: Bytes) -> io::Result<()> {
        loop {
            let notified = self.shared.status.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.shared.state.lock().unwrap();
                if state.closed {
                    return Err(closed());
                }
                match state
                    .connection
                    .as_mut()
                    .unwrap()
                    .dgram_send_buf(frame.clone())
                {
                    Ok(()) => {
                        drop(state);
                        self.shared.changed.notify_one();
                        return Ok(());
                    }
                    Err(quiche::Error::Done) => {}
                    Err(quiche::Error::BufferTooShort) => {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    Err(error) => return Err(failure(error)),
                }
            }
            notified.await;
        }
    }
    pub(crate) async fn read_datagram(&self, id: u64) -> io::Result<Bytes> {
        poll_fn(|cx| {
            let mut state = self.shared.state.lock().unwrap();
            if state.closed {
                return Poll::Ready(Err(closed()));
            }
            let body = state.streams.get_mut(&id).ok_or_else(closed)?;
            if body.failed || body.finished || !body.receive_owned {
                return Poll::Ready(Err(closed()));
            }
            let queue = body.datagrams.as_mut().ok_or_else(closed)?;
            if let Some(frame) = queue.pop_front() {
                Poll::Ready(Ok(frame))
            } else {
                // The owner also holds State when delivering progress. Only
                // blocked operations register, with no gap for a lost wake.
                body.signals.datagram.register(cx.waker());
                Poll::Pending
            }
        })
        .await
    }
}
fn request_headers(request: &Request<()>) -> io::Result<Vec<quiche::h3::Header>> {
    let mut headers = vec![quiche::h3::Header::new(
        b":method",
        request.method().as_str().as_bytes(),
    )];
    let connect = request.method() == http::Method::CONNECT;
    let protocol = request.extensions().get::<Protocol>();
    if !connect || protocol.is_some() {
        headers.push(quiche::h3::Header::new(
            b":scheme",
            request.uri().scheme_str().ok_or_else(invalid)?.as_bytes(),
        ));
        headers.push(quiche::h3::Header::new(
            b":path",
            request
                .uri()
                .path_and_query()
                .map_or("/", |path| path.as_str())
                .as_bytes(),
        ));
    }
    headers.push(quiche::h3::Header::new(
        b":authority",
        request
            .uri()
            .authority()
            .ok_or_else(invalid)?
            .as_str()
            .as_bytes(),
    ));
    if let Some(protocol) = protocol {
        headers.push(quiche::h3::Header::new(b":protocol", protocol.0.as_bytes()));
    }
    for (name, value) in request.headers() {
        if name != http::header::HOST {
            headers.push(quiche::h3::Header::new(
                name.as_str().as_bytes(),
                value.as_bytes(),
            ));
        }
    }
    if headers
        .iter()
        .map(|header| header.name().len() + header.value().len())
        .sum::<usize>()
        > CHUNK
    {
        return Err(invalid());
    }
    Ok(headers)
}
pub(crate) struct RequestStream {
    send: SendStream,
    receive: RecvStream,
}
impl RequestStream {
    pub(crate) fn id(&self) -> StreamId {
        StreamId(self.send.id)
    }
    pub(crate) fn split(self) -> (SendStream, RecvStream) {
        (self.send, self.receive)
    }
}
pub(crate) struct StreamId(u64);
impl StreamId {
    pub(crate) fn into_inner(self) -> u64 {
        self.0
    }
}
pub(crate) struct SendStream {
    client: Client,
    id: u64,
    signals: Arc<Signals>,
}
impl SendStream {
    pub(crate) async fn send_data(&mut self, mut data: Bytes) -> io::Result<()> {
        while !data.is_empty() {
            let maximum = data.len().min(CHUNK);
            let mut chunk = data.slice(..maximum);
            let n = poll_fn(|cx| {
                let mut state = self.client.shared.state.lock().unwrap();
                if state.closed
                    || state
                        .streams
                        .get(&self.id)
                        .is_none_or(|body| body.failed || !body.send_owned || body.send_finished)
                {
                    return Poll::Ready(Err(closed()));
                }
                let State { connection, h3, .. } = &mut *state;
                match h3.as_mut().unwrap().send_body_zc(
                    connection.as_mut().unwrap(),
                    self.id,
                    &mut chunk,
                    false,
                ) {
                    Ok(n) if n > 0 => {
                        drop(state);
                        self.client.shared.changed.notify_one();
                        Poll::Ready(Ok(n))
                    }
                    Ok(_) | Err(quiche::h3::Error::Done) => {
                        self.signals.write.register(cx.waker());
                        Poll::Pending
                    }
                    Err(error) => Poll::Ready(Err(failure(error))),
                }
            })
            .await?;
            data.advance(n);
        }
        Ok(())
    }
    pub(crate) async fn finish(&mut self) -> io::Result<()> {
        poll_fn(|cx| {
            let mut state = self.client.shared.state.lock().unwrap();
            if state.closed
                || state
                    .streams
                    .get(&self.id)
                    .is_none_or(|body| body.failed || !body.send_owned)
            {
                return Poll::Ready(Err(closed()));
            }
            if state.streams[&self.id].send_finished {
                return Poll::Ready(Ok(()));
            }
            let State { connection, h3, .. } = &mut *state;
            match h3
                .as_mut()
                .unwrap()
                .send_body(connection.as_mut().unwrap(), self.id, &[], true)
            {
                Ok(_) => {
                    state.streams.get_mut(&self.id).unwrap().send_finished = true;
                    drop(state);
                    self.client.shared.changed.notify_one();
                    Poll::Ready(Ok(()))
                }
                Err(quiche::h3::Error::Done) => {
                    self.signals.write.register(cx.waker());
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(failure(error))),
            }
        })
        .await
    }
    pub(crate) fn stop_stream(&mut self, code: u64) {
        stop_half(&self.client, self.id, true, code);
    }
}
impl Drop for SendStream {
    fn drop(&mut self) {
        stop_half(&self.client, self.id, true, REQUEST_CANCELLED);
    }
}
pub(crate) struct RecvStream {
    client: Client,
    id: u64,
    signals: Arc<Signals>,
}
impl RecvStream {
    pub(crate) async fn recv_response(&mut self) -> io::Result<Response<()>> {
        poll_fn(|cx| {
            let mut state = self.client.shared.state.lock().unwrap();
            if state.closed {
                return Poll::Ready(Err(closed()));
            }
            let Some(body) = state.streams.get_mut(&self.id) else {
                return Poll::Ready(Err(closed()));
            };
            if body.failed || !body.receive_owned {
                return Poll::Ready(Err(closed()));
            }
            if let Some(headers) = body.headers.take() {
                return Poll::Ready(Ok(headers));
            }
            if body.finished {
                return Poll::Ready(Err(invalid()));
            }
            self.signals.read.register(cx.waker());
            Poll::Pending
        })
        .await
    }
    pub(crate) fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Bytes>>> {
        let mut state = self.client.shared.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(closed()));
        }
        let Some(body) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed()));
        };
        if body.failed || !body.receive_owned {
            return Poll::Ready(Err(closed()));
        }
        if let Some(data) = body.data.pop_front() {
            body.buffered -= data.len();
            drop(state);
            self.client.shared.changed.notify_one();
            return Poll::Ready(Ok(Some(data)));
        }
        if body.finished {
            return Poll::Ready(Ok(None));
        }
        self.signals.read.register(cx.waker());
        Poll::Pending
    }
    pub(crate) fn stop_sending(&mut self, code: u64) {
        stop_half(&self.client, self.id, false, code);
    }
}
impl Drop for RecvStream {
    fn drop(&mut self) {
        stop_half(&self.client, self.id, false, REQUEST_CANCELLED);
    }
}
fn stop_half(client: &Client, id: u64, send: bool, code: u64) {
    let mut state = client.shared.state.lock().unwrap();
    let Some(body) = state.streams.get_mut(&id) else {
        return;
    };
    let owned = if send {
        &mut body.send_owned
    } else {
        &mut body.receive_owned
    };
    if !*owned {
        return;
    }
    *owned = false;
    let graceful = if send {
        body.send_finished
    } else {
        body.finished
    };
    if !send {
        body.data.clear();
        body.buffered = 0;
        body.datagrams.take();
    }
    let remove = !body.send_owned && !body.receive_owned;
    if !graceful {
        let _ = state.connection.as_mut().unwrap().stream_shutdown(
            id,
            if send {
                quiche::Shutdown::Write
            } else {
                quiche::Shutdown::Read
            },
            code,
        );
    }
    if remove {
        state.streams.remove(&id);
    }
    drop(state);
    client.shared.changed.notify_one();
}
fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1 << (first >> 6);
    if bytes.len() < len {
        return None;
    }
    let mut value = u64::from(first & 63);
    for byte in &bytes[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn closed() -> io::Error {
    io::ErrorKind::ConnectionAborted.into()
}
fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("HTTP/3 transport failed")
}

/// Meta BBR labels select the public quiche BBRv2 controller.
pub(crate) fn congestion_controller(name: &str) -> Option<quiche::CongestionControlAlgorithm> {
    Some(match name {
        "cubic" => quiche::CongestionControlAlgorithm::CUBIC,
        "new_reno" => quiche::CongestionControlAlgorithm::Reno,
        "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => {
            quiche::CongestionControlAlgorithm::Bbr2Gcongestion
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dispatch::DispatchError,
        security::{SecurityContext, StandardTlsClient, TlsClientOptions, TlsVersions},
        session::{Datagram, Destination},
    };
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    struct Packets {
        send: mpsc::Sender<Bytes>,
        receive: mpsc::Receiver<Bytes>,
        peer: SocketAddr,
        closed: Arc<std::sync::atomic::AtomicBool>,
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
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
            self.receive.close();
            Ok(())
        }
    }

    /// Real TLS/QUIC/HTTP3 peer entirely in bounded memory channels. The server
    /// sends unsolicited flow IDs without allowing those IDs to admit clients.
    async fn peer(
        mut packets: mpsc::Receiver<Bytes>,
        outgoing: mpsc::Sender<Bytes>,
        mut config: quiche::Config,
        cancel: CancellationToken,
        flood: usize,
        progress: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let local: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let remote: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let first = tokio::select! {
            () = cancel.cancelled() => return,
            first = packets.recv() => first,
        };
        let Some(mut first) = first.map(|packet| packet.to_vec()) else {
            return;
        };
        let header = quiche::Header::from_slice(&mut first, 20).unwrap();
        let cid = header.dcid.into_owned();
        let mut connection = quiche::accept(&cid, None, local, remote, &mut config).unwrap();
        connection
            .recv(
                &mut first,
                quiche::RecvInfo {
                    from: remote,
                    to: local,
                },
            )
            .unwrap();
        let mut h3 = None;
        let mut request = None;
        let mut flooded = 0;
        let mut response = false;
        let mut legitimate = false;
        let mut buf = [0; 1400];
        let mut pending = None;
        loop {
            if connection.is_established() && h3.is_none() {
                let mut config = quiche::h3::Config::new().unwrap();
                config.enable_extended_connect(true);
                h3 =
                    Some(quiche::h3::Connection::with_transport(&mut connection, &config).unwrap());
            }
            if let Some(h3) = h3.as_mut() {
                while let Ok((id, event)) = h3.poll(&mut connection) {
                    if let quiche::h3::Event::Headers { list, .. } = event {
                        assert!(list.iter().any(|header| header.name() == b":protocol"
                            && header.value() == b"cf-connect-ip"));
                        request = Some(id);
                    }
                }
                if let Some(id) = request {
                    if !response {
                        match h3.send_response(
                            &mut connection,
                            id,
                            &[quiche::h3::Header::new(b":status", b"200")],
                            false,
                        ) {
                            Ok(()) => response = true,
                            Err(quiche::h3::Error::StreamBlocked) => {}
                            Err(error) => panic!("{error:?}"),
                        }
                    }
                    for _ in 0..64 {
                        if flooded < flood {
                            // Each unknown request-flow ID fits one two-byte
                            // varint and has no associated admitted stream.
                            let flow = 0x4000_u16 | (1000 + flooded) as u16;
                            let mut frame = flow.to_be_bytes().to_vec();
                            frame.push(0);
                            frame.extend_from_slice(&[0x55; 128]);
                            match connection.dgram_send(&frame) {
                                Ok(()) => {
                                    flooded += 1;
                                    progress.store(flooded, std::sync::atomic::Ordering::Release);
                                }
                                Err(quiche::Error::Done) => break,
                                Err(error) => panic!("{error:?}"),
                            }
                        } else if !legitimate {
                            let frame = [((id / 4) as u8), 0, 0x42];
                            match connection.dgram_send(&frame) {
                                Ok(()) => legitimate = true,
                                Err(quiche::Error::Done) => {}
                                Err(error) => panic!("{error:?}"),
                            }
                            break;
                        } else {
                            break;
                        }
                    }
                }
            }
            // One pending output packet keeps a full memory channel from
            // blocking peer receive/ACK processing on this same task.
            if pending.is_none() {
                match connection.send(&mut buf) {
                    Ok((n, info)) => {
                        pending = Some((Bytes::copy_from_slice(&buf[..n]), info.at));
                    }
                    Err(quiche::Error::Done) => {}
                    Err(error) => panic!("{error:?}"),
                }
            }
            if connection.is_closed() {
                // A remote QUIC close does not close a physical UDP socket.
                // Keep the memory transport alive through the client's Stop.
                cancel.cancelled().await;
                break;
            }
            let now = std::time::Instant::now();
            let deadline = connection
                .timeout()
                .map(|delay| now + delay)
                .into_iter()
                .chain(
                    pending
                        .as_ref()
                        .filter(|(_, at)| *at > now)
                        .map(|(_, at)| *at),
                )
                .min()
                .unwrap_or(now + Duration::from_secs(2));
            tokio::select! {
                () = cancel.cancelled() => break,
                received = packets.recv() => {
                    let Some(received) = received else { break; };
                    let mut received = received.to_vec();
                    let _ = connection.recv(&mut received, quiche::RecvInfo { from: remote, to: local });
                },
                permit = outgoing.reserve(), if pending.as_ref().is_some_and(|(_, at)| *at <= now) => {
                    let Ok(permit) = permit else { break; };
                    permit.send(pending.take().unwrap().0);
                },
                () = tokio::time::sleep_until(deadline.into()) => {
                    if connection.timeout().is_some_and(|delay| delay.is_zero()) {
                        connection.on_timeout();
                    }
                },
            }
        }
    }

    #[tokio::test]
    async fn quiche_h3_memory_failed_preparation_closes_owned_transport_without_sending() {
        let tls = StandardTlsClient::with_options(
            &SecurityContext::new(),
            "localhost",
            TlsClientOptions {
                alpn: vec![b"h3".to_vec()],
                required_alpn: Some(b"h3".to_vec()),
                versions: TlsVersions::Tls13,
                ..Default::default()
            },
            0,
            BODY_LIMIT,
        )
        .unwrap()
        .quiche_config()
        .unwrap();
        let (send, mut sent) = mpsc::channel(32);
        let (_incoming, receive) = mpsc::channel(32);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer = "192.0.2.1:443".parse().unwrap();
        let result = Driver::new(
            Transport {
                transport: Box::new(Packets {
                    send,
                    receive,
                    peer,
                    closed: closed.clone(),
                }),
                peer,
                budget: DatagramBudget::new(1400, 1400),
                tls,
                server_name: "another.invalid".into(),
            },
            Default::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(closed.load(std::sync::atomic::Ordering::Acquire));
        assert!(sent.recv().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quiche_h3_memory_isolated_initial_loss_uses_fresh_pto_and_joins_stop() {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let tls = StandardTlsClient::with_options(
            &SecurityContext::with_tls_roots(roots),
            "localhost",
            TlsClientOptions {
                alpn: vec![b"h3".to_vec()],
                required_alpn: Some(b"h3".to_vec()),
                versions: TlsVersions::Tls13,
                ..Default::default()
            },
            0,
            BODY_LIMIT,
        )
        .unwrap()
        .quiche_config()
        .unwrap();
        let mut builder =
            boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
        builder
            .set_certificate(&boring::x509::X509::from_der(identity.cert.der()).unwrap())
            .unwrap();
        builder
            .set_private_key(
                &boring::pkey::PKey::private_key_from_der(&identity.signing_key.serialize_der())
                    .unwrap(),
            )
            .unwrap();
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder).unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_curves_list("X25519").unwrap();
        config.verify_peer(false);
        config.set_max_idle_timeout(10000);
        config.set_max_send_udp_payload_size(1400);
        config.set_max_recv_udp_payload_size(1400);
        config.set_initial_max_data(1024 * 1024);
        config.set_initial_max_stream_data_bidi_remote(128 * 1024);
        config.set_initial_max_stream_data_bidi_local(128 * 1024);
        config.set_initial_max_stream_data_uni(16 * 1024);
        config.set_initial_max_streams_bidi(256);
        config.set_initial_max_streams_uni(8);
        config.enable_dgram(true, 64, 64);
        let (to_server, mut from_client) = mpsc::channel(32);
        let (to_client, from_server) = mpsc::channel(32);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (client, driver) = Driver::new(
            Transport {
                transport: Box::new(Packets {
                    send: to_server,
                    receive: from_server,
                    peer: "192.0.2.1:443".parse().unwrap(),
                    closed: closed.clone(),
                }),
                peer: "192.0.2.1:443".parse().unwrap(),
                budget: DatagramBudget::new(1400, 1400),
                tls,
                server_name: "localhost".into(),
            },
            Options {
                datagrams: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // Keep this loss probe to a single Initial. A large PQ ClientHello
        // could require paced extra packets that wake the old driver by chance.
        {
            let mut state = client.shared.state.lock().unwrap();
            let ssl: &mut boring::ssl::SslRef = state.connection.as_mut().unwrap().as_mut();
            ssl.set_curves_list("X25519").unwrap();
        }
        let server_cancel = CancellationToken::new();
        let peer_cancel = server_cancel.clone();
        let (dropped, observed_drop) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(async move {
            let first = tokio::select! {
                () = peer_cancel.cancelled() => return,
                first = from_client.recv() => first,
            };
            let Some(mut first) = first.map(|packet: Bytes| packet.to_vec()) else {
                return;
            };
            let initial = quiche::Header::from_slice(&mut first, 20)
                .is_ok_and(|header| header.ty == quiche::Type::Initial);
            // No input, app request or synthetic wake reaches the driver until
            // its real native PTO produces another packet after this loss.
            let _ = dropped.send(initial);
            if initial {
                peer(
                    from_client,
                    to_client,
                    config,
                    peer_cancel,
                    0,
                    Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                )
                .await;
            }
        });
        let cancel = CancellationToken::new();
        let mut task = tokio::spawn(driver.run(cancel.clone()));
        let result = tokio::time::timeout(Duration::from_secs(4), async {
            if !observed_drop
                .await
                .map_err(|_| "Initial drop was not witnessed")?
            {
                return Err("the dropped packet was not an Initial");
            }
            let (fresh_pto, first_flight) = {
                let state = client.shared.state.lock().unwrap();
                let connection = state.connection.as_ref().unwrap();
                (connection.timeout(), connection.stats().sent)
            };
            let fresh_pto = fresh_pto.ok_or("native send did not arm its PTO")?;
            if first_flight != 1 || fresh_pto > Duration::from_secs(2) {
                return Err("the first lost Initial was not an isolated flight");
            }
            tokio::time::timeout(fresh_pto + Duration::from_millis(500), client.ready(true))
                .await
                .map_err(|_| "isolated Initial loss did not recover at the fresh PTO")?
                .map_err(|_| "native H3 preparation failed after Initial loss")
        })
        .await;
        // Retire and join both sides before asserting, including the RED path
        // where the server has not received its first surviving Initial.
        cancel.cancel();
        let driver_join = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
        let driver_stopped = matches!(driver_join, Ok(Ok(Ok(()))));
        if driver_join.is_err() {
            task.abort();
            let _ = task.await;
        }
        server_cancel.cancel();
        let server_join = tokio::time::timeout(Duration::from_secs(2), &mut server).await;
        let server_stopped = matches!(server_join, Ok(Ok(())));
        if server_join.is_err() {
            server.abort();
            let _ = server.await;
        }
        assert!(matches!(&result, Ok(Ok(()))), "{result:?}");
        assert!(
            driver_stopped,
            "client driver failed to stop and join: {driver_join:?}"
        );
        assert!(
            server_stopped,
            "server failed to stop and join: {server_join:?}"
        );
        assert!(closed.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn quiche_h3_memory_settings_unknown_flow_dispatch_and_joined_stop() {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let tls = StandardTlsClient::with_options(
            &SecurityContext::with_tls_roots(roots),
            "localhost",
            TlsClientOptions {
                alpn: vec![b"h3".to_vec()],
                required_alpn: Some(b"h3".to_vec()),
                versions: TlsVersions::Tls13,
                ..Default::default()
            },
            0,
            BODY_LIMIT,
        )
        .unwrap()
        .quiche_config()
        .unwrap();
        let mut builder =
            boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
        builder
            .set_certificate(&boring::x509::X509::from_der(identity.cert.der()).unwrap())
            .unwrap();
        builder
            .set_private_key(
                &boring::pkey::PKey::private_key_from_der(&identity.signing_key.serialize_der())
                    .unwrap(),
            )
            .unwrap();
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder).unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.verify_peer(false);
        config.set_max_idle_timeout(10000);
        config.set_max_send_udp_payload_size(1400);
        config.set_max_recv_udp_payload_size(1400);
        config.set_initial_max_data(1024 * 1024);
        config.set_initial_max_stream_data_bidi_remote(128 * 1024);
        config.set_initial_max_stream_data_bidi_local(128 * 1024);
        config.set_initial_max_stream_data_uni(16 * 1024);
        config.set_initial_max_streams_bidi(256);
        config.set_initial_max_streams_uni(8);
        config.enable_dgram(true, 64, 64);
        let (to_server, from_client) = mpsc::channel(32);
        let (to_client, from_server) = mpsc::channel(32);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_cancel = CancellationToken::new();
        let flooded = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = tokio::spawn(peer(
            from_client,
            to_client,
            config,
            server_cancel.clone(),
            10_000,
            flooded.clone(),
        ));
        let (mut client, driver) = Driver::new(
            Transport {
                transport: Box::new(Packets {
                    send: to_server,
                    receive: from_server,
                    peer: "192.0.2.1:443".parse().unwrap(),
                    closed: closed.clone(),
                }),
                peer: "192.0.2.1:443".parse().unwrap(),
                budget: DatagramBudget::new(1400, 1400),
                tls,
                server_name: "localhost".into(),
            },
            Options {
                datagrams: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(driver.run(cancel.clone()));
        let phase = std::sync::atomic::AtomicUsize::new(0);
        let retained_ready_wakers = std::sync::atomic::AtomicUsize::new(0);
        let operation = async {
            client.ready(true).await.unwrap();
            phase.store(1, std::sync::atomic::Ordering::Release);
            let mut request = Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.invalid/")
                .body(())
                .unwrap();
            request.extensions_mut().insert(Protocol::CF_CONNECT_IP);
            let stream = client.send_request(request).await.unwrap();
            let id = stream.id().into_inner();
            client.register_datagrams(id).unwrap();
            let (mut send, mut receive) = stream.split();
            assert_eq!(receive.recv_response().await.unwrap().status(), 200);
            retained_ready_wakers.fetch_add(
                usize::from(receive.signals.read.take().is_some()),
                std::sync::atomic::Ordering::Relaxed,
            );
            send.send_data(Bytes::from_static(b"accepted"))
                .await
                .unwrap();
            retained_ready_wakers.fetch_add(
                usize::from(send.signals.write.take().is_some()),
                std::sync::atomic::Ordering::Relaxed,
            );
            phase.store(2, std::sync::atomic::Ordering::Release);
            assert_eq!(
                client.read_datagram(id).await.unwrap().as_ref(),
                &[0, 0, 0x42]
            );
            let state = client.shared.state.lock().unwrap();
            retained_ready_wakers.fetch_add(
                usize::from(state.streams[&id].signals.datagram.take().is_some()),
                std::sync::atomic::Ordering::Relaxed,
            );
            assert_eq!(state.streams.len(), 1);
            assert!(state.streams[&id].datagrams.as_ref().unwrap().len() <= DATAGRAM_QUEUE);
            assert_eq!(
                state
                    .settings
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|&&(setting, _)| setting == 0x33)
                    .unwrap()
                    .1,
                1
            );
        };
        let result = tokio::time::timeout(Duration::from_secs(10), operation).await;
        cancel.cancel();
        let _ = task.await.unwrap();
        server_cancel.cancel();
        server.await.unwrap();
        assert!(closed.load(std::sync::atomic::Ordering::Acquire));
        assert!(client.close_reason().is_some());
        assert!(client.shared.state.lock().unwrap().connection.is_none());
        assert!(client.shared.state.lock().unwrap().streams.is_empty());
        assert_eq!(
            retained_ready_wakers.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "completed H3 operations retained waiters after successful progress"
        );
        assert!(
            result.is_ok(),
            "memory H3 timed out at phase {}, unknown frames enqueued {}",
            phase.load(std::sync::atomic::Ordering::Acquire),
            flooded.load(std::sync::atomic::Ordering::Acquire)
        );
    }
}
