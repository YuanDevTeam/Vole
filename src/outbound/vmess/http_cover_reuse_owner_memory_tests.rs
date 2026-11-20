//! Complete VMess/HTTP owner tests over IO-only memory dependencies.
//! The finite HTTP head is not a VMess authenticated response. No peer task,
//! socket, resolver, successful body-auth claim or replacement owner is used.
use super::*;
use crate::{
    config::{Config, ProxyProtocol},
    session::InboundKind,
};
use futures_util::task::{ArcWake, waker};
use std::{
    collections::VecDeque,
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CIPHERS: [&str; 4] = ["auto", "none", "aes-128-gcm", "chacha20-poly1305"];

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(owner: &Arc<Self>) {
        owner.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct RawReceipt {
    reads: AtomicUsize,
    writes: AtomicUsize,
    flushes: AtomicUsize,
    shutdowns: AtomicUsize,
    drops: AtomicUsize,
    pending_writes: AtomicUsize,
    blocked: AtomicBool,
    response: Mutex<VecDeque<u8>>,
    submitted: Mutex<Vec<u8>>,
}
impl RawReceipt {
    fn polls(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
            + self.writes.load(Ordering::SeqCst)
            + self.flushes.load(Ordering::SeqCst)
            + self.shutdowns.load(Ordering::SeqCst)
    }
    fn one_cover(&self) -> bool {
        let bytes = self.submitted.lock().unwrap();
        let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            return false;
        };
        let Ok(head) = std::str::from_utf8(&bytes[..end + 4]) else {
            return false;
        };
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.parse::<usize>().ok());
        head.starts_with("GET /memory-cover HTTP/1.1\r\n")
            && head.contains("host: cover.memory.invalid\r\n")
            && length.is_some_and(|length| length > 0 && bytes.len() >= end + 4 + length)
            && bytes
                .windows(b"GET /memory-cover HTTP/1.1".len())
                .filter(|part| *part == b"GET /memory-cover HTTP/1.1")
                .count()
                == 1
    }
}
struct Raw {
    state: Arc<RawReceipt>,
    read_wait: Option<Waker>,
    write_wait: Option<Waker>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsyncRead for Raw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.reads.fetch_add(1, Ordering::SeqCst);
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut response = this.state.response.lock().unwrap();
        if response.is_empty() {
            this.read_wait = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while output.remaining() != 0 {
            let Some(byte) = response.pop_front() else {
                break;
            };
            output.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Raw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.state.writes.fetch_add(1, Ordering::SeqCst);
        if this.state.blocked.load(Ordering::SeqCst) {
            this.write_wait = Some(cx.waker().clone());
            this.state.pending_writes.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending;
        }
        let mut submitted = this.state.submitted.lock().unwrap();
        if input.len() > 16 * 1024 - submitted.len() {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        submitted.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.flushes.fetch_add(1, Ordering::SeqCst);
        if this.state.blocked.load(Ordering::SeqCst) {
            this.write_wait = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.as_mut().poll_flush(cx)
    }
}
struct MemoryUpstream {
    streams: Mutex<VecDeque<BoxStream>>,
    calls: AtomicUsize,
}
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let io = self
            .streams
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(DispatchError::NotAllowed)?;
        Ok(ConnectedStream {
            io,
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn config(cipher: &str) -> VmessOutboundConfig {
    let value = serde_json::json!({"proxies":[{"name":"cover","type":"vmess",
        "server":"192.0.2.10","port":8443,"uuid":"07070707-0707-0707-0707-070707070707",
        "cipher":cipher,"network":"http","http-opts":{"method":"GET","path":["/memory-cover"],
        "headers":{"Host":["cover.memory.invalid"]}}}],"rules":["MATCH,cover"]});
    let mut parsed = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
    let ProxyProtocol::Vmess(config) = parsed.proxies.remove(0).protocol else {
        panic!("actual VMess Config")
    };
    config
}
fn fixture(
    cipher: &str,
    count: usize,
    cover_response: bool,
) -> (VmessOutbound, Arc<MemoryUpstream>, Vec<Arc<RawReceipt>>) {
    let states: Vec<_> =
        (0..count)
            .map(|_| {
                let state = Arc::new(RawReceipt::default());
                if cover_response {
                    state.response.lock().unwrap().extend(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n",
                    );
                }
                state
            })
            .collect();
    let upstream = Arc::new(MemoryUpstream {
        streams: Mutex::new(
            states
                .iter()
                .map(|state| {
                    Box::new(Raw {
                        state: state.clone(),
                        read_wait: None,
                        write_wait: None,
                    }) as BoxStream
                })
                .collect(),
        ),
        calls: AtomicUsize::new(0),
    });
    let node = VmessOutbound::new_with_path(&config(cipher), UpstreamPath::proxy(upstream.clone()))
        .unwrap();
    (node, upstream, states)
}
fn session() -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: Destination::Ip("192.0.2.2:443".parse().unwrap()),
        sniffed_domain: None,
    }
}
async fn connect(node: &VmessOutbound) -> BoxStream {
    let context = EstablishContext::with_timeout(Duration::from_secs(1));
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        node.connect_stream(session(), &context),
    )
    .await;
    match result {
        Ok(Ok(connected)) => connected.io,
        other => {
            OutboundConnector::shutdown(node).await;
            panic!("real complete VMess HTTP setup did not finish: {other:?}");
        }
    }
}
fn read_poll(stream: &mut BoxStream, wake: &Waker) -> Poll<io::Result<()>> {
    let mut storage = [0; 1];
    Pin::new(stream).poll_read(
        &mut Context::from_waker(wake),
        &mut ReadBuf::new(&mut storage),
    )
}
fn kind<T>(result: Poll<io::Result<T>>) -> Option<io::ErrorKind> {
    match result {
        Poll::Ready(Err(error)) => Some(error.kind()),
        _ => None,
    }
}
fn released(weak: &Weak<RawReceipt>, reader: &Weak<WakeCount>, writer: &Weak<WakeCount>) -> bool {
    weak.upgrade().is_none() && reader.upgrade().is_none() && writer.upgrade().is_none()
}

#[tokio::test]
async fn vmess_http_cover_complete_owned_whole_close_control_releases_raw() {
    for cipher in CIPHERS {
        let (node, upstream, states) = fixture(cipher, 1, false);
        let state = states[0].clone();
        let weak = Arc::downgrade(&state);
        let mut stream = connect(&node).await;
        let reader = Arc::new(WakeCount::default());
        let writer = Arc::new(WakeCount::default());
        let reader_weak = Arc::downgrade(&reader);
        let writer_weak = Arc::downgrade(&writer);
        let rx = waker(reader.clone());
        let tx = waker(writer.clone());
        let pending_read = read_poll(&mut stream, &rx).is_pending();
        let accepted = matches!(
            Pin::new(&mut stream).poll_write(&mut Context::from_waker(&tx), b"whole close upload"),
            Poll::Ready(Ok(18))
        );
        // Accepting buffered output now wakes the parked reader. Consume that
        // notification and genuinely rearm it before observing whole-close.
        let pending_before_close = read_poll(&mut stream, &rx).is_pending();
        reader.0.store(0, Ordering::SeqCst);
        let closed = matches!(
            Pin::new(&mut stream).poll_shutdown(&mut Context::from_waker(&tx)),
            Poll::Ready(Ok(()))
        );
        let woke = reader.0.load(Ordering::SeqCst) > 0;
        let raw_released_while_stream_alive = state.drops.load(Ordering::SeqCst) == 1;
        let read_after_close = kind(read_poll(&mut stream, &rx));
        let cover_once = state.one_cover();
        let no_physical_shutdown = state.shutdowns.load(Ordering::SeqCst) == 0;
        OutboundConnector::shutdown(&node).await;
        let joined = node.tasks.is_closed() && node.tasks.is_empty();
        drop(stream);
        drop(node);
        drop(upstream);
        drop(states);
        drop(state);
        drop(rx);
        drop(tx);
        drop(reader);
        drop(writer);
        let owners_released = released(&weak, &reader_weak, &writer_weak);
        assert!(
            pending_read
                && accepted
                && pending_before_close
                && closed
                && woke
                && cover_once
                && no_physical_shutdown,
            "actual complete whole-close control failed for {cipher}"
        );
        assert_eq!(read_after_close, Some(io::ErrorKind::ConnectionAborted));
        assert!(raw_released_while_stream_alive && joined && owners_released);
    }
}

#[tokio::test]
async fn vmess_http_cover_complete_owned_stop_wakes_independent_read_and_write_callers() {
    let mut observations = Vec::new();
    for cipher in CIPHERS {
        for response in [false, true] {
            for operation in ["write", "flush", "shutdown"] {
                let (node, upstream, states) = fixture(cipher, 1, response);
                let state = states[0].clone();
                let weak = Arc::downgrade(&state);
                let mut stream = connect(&node).await;
                let reader = Arc::new(WakeCount::default());
                let writer = Arc::new(WakeCount::default());
                let reader_weak = Arc::downgrade(&reader);
                let writer_weak = Arc::downgrade(&writer);
                let rx = waker(reader.clone());
                let tx = waker(writer.clone());
                state.blocked.store(true, Ordering::SeqCst);
                let accepted = matches!(
                    Pin::new(&mut stream)
                        .poll_write(&mut Context::from_waker(&tx), b"pending upload"),
                    Poll::Ready(Ok(14))
                );
                let read_pending = read_poll(&mut stream, &rx).is_pending();
                let write_pending = match operation {
                    "write" => Pin::new(&mut stream)
                        .poll_write(&mut Context::from_waker(&tx), b"second")
                        .is_pending(),
                    "flush" => Pin::new(&mut stream)
                        .poll_flush(&mut Context::from_waker(&tx))
                        .is_pending(),
                    _ => Pin::new(&mut stream)
                        .poll_shutdown(&mut Context::from_waker(&tx))
                        .is_pending(),
                };
                let genuine_raw_pending = state.pending_writes.load(Ordering::SeqCst) > 0;
                reader.0.store(0, Ordering::SeqCst);
                writer.0.store(0, Ordering::SeqCst);
                OutboundConnector::begin_shutdown(&node);
                // These snapshots precede every post-stop IO poll, event and Drop.
                let read_woken_at_stop = reader.0.load(Ordering::SeqCst) > 0;
                let write_woken_at_stop = writer.0.load(Ordering::SeqCst) > 0;
                let read_error = kind(read_poll(&mut stream, &rx));
                let write_error = kind(
                    Pin::new(&mut stream).poll_write(&mut Context::from_waker(&tx), b"no replay"),
                );
                let raw_released = state.drops.load(Ordering::SeqCst) == 1;
                let cover_once = state.one_cover();
                OutboundConnector::shutdown(&node).await;
                let joined = node.tasks.is_closed() && node.tasks.is_empty();
                drop(stream);
                drop(node);
                drop(upstream);
                drop(states);
                drop(state);
                drop(rx);
                drop(tx);
                drop(reader);
                drop(writer);
                let owners_released = released(&weak, &reader_weak, &writer_weak);
                observations.push((
                    cipher,
                    response,
                    operation,
                    accepted && read_pending && write_pending && genuine_raw_pending,
                    read_woken_at_stop,
                    write_woken_at_stop,
                    read_error,
                    write_error,
                    raw_released && cover_once && joined && owners_released,
                ));
            }
        }
    }
    assert_eq!(observations.len(), 24);
    assert!(
        observations
            .iter()
            .all(|(_, _, _, pending, _, _, read, write, cleanup)| *pending
                && *read == Some(io::ErrorKind::ConnectionAborted)
                && *write == Some(io::ErrorKind::ConnectionAborted)
                && *cleanup),
        "real Pending/cancellation/cleanup fixture failed: {observations:?}"
    );
    assert!(
        observations
            .iter()
            .all(|(_, _, _, _, rx, tx, _, _, _)| *rx && *tx),
        "parent Stop must wake both unrelated callers before any repoll/Drop: {observations:?}"
    );
}

#[tokio::test]
async fn vmess_http_cover_actual_prepare_stop_before_finish_never_polls_raw_again() {
    for cipher in CIPHERS {
        let (node, upstream, states) = fixture(cipher, 1, false);
        let weak = Arc::downgrade(&states[0]);
        let context = EstablishContext::with_timeout(Duration::from_secs(1));
        let prepared = match node.prepare(session(), &context).await {
            Ok(prepared) => prepared,
            Err(error) => {
                OutboundConnector::shutdown(&node).await;
                panic!("real prepared HTTP owner failed before Stop: {error:?}");
            }
        };
        let before = states[0].polls();
        let token_was_open = !prepared.token.is_cancelled();
        OutboundConnector::begin_shutdown(&node);
        let stopped_child = prepared.token.is_cancelled();
        let finished = prepared.finish(Command::Tcp, &session().destination).await;
        let rejected = finished.is_err();
        drop(finished);
        let calls = upstream.calls.load(Ordering::SeqCst);
        let after_stop = node.connect_stream(session(), &context).await;
        let rejects_new = after_stop.is_err();
        drop(after_stop);
        let no_new_raw =
            states[0].polls() == before && upstream.calls.load(Ordering::SeqCst) == calls;
        let raw_dropped = states[0].drops.load(Ordering::SeqCst) == 1;
        OutboundConnector::shutdown(&node).await;
        let joined = node.tasks.is_closed() && node.tasks.is_empty();
        drop(node);
        drop(upstream);
        drop(states);
        let owners_released = weak.upgrade().is_none();
        assert!(
            token_was_open
                && stopped_child
                && rejected
                && rejects_new
                && no_new_raw
                && raw_dropped
                && joined
                && owners_released,
            "real prepare/Stop/finish must not publish or touch raw IO: {cipher}"
        );
    }
}

#[tokio::test]
async fn vmess_http_cover_complete_child_drop_preserves_sibling_until_parent_stop() {
    for cipher in CIPHERS {
        let (node, upstream, states) = fixture(cipher, 2, false);
        let weak_one = Arc::downgrade(&states[0]);
        let weak_two = Arc::downgrade(&states[1]);
        let first = connect(&node).await;
        let mut second = connect(&node).await;
        drop(first);
        let isolated = states[0].drops.load(Ordering::SeqCst) == 1
            && states[1].drops.load(Ordering::SeqCst) == 0
            && !node.cancellation.is_cancelled();
        let reader = Arc::new(WakeCount::default());
        let writer = Arc::new(WakeCount::default());
        let reader_weak = Arc::downgrade(&reader);
        let writer_weak = Arc::downgrade(&writer);
        let rx = waker(reader.clone());
        let tx = waker(writer.clone());
        let accepted = matches!(
            Pin::new(&mut second).poll_write(&mut Context::from_waker(&tx), b"live sibling"),
            Poll::Ready(Ok(12))
        );
        let flushed = matches!(
            Pin::new(&mut second).poll_flush(&mut Context::from_waker(&tx)),
            Poll::Ready(Ok(()))
        );
        let pending_read = read_poll(&mut second, &rx).is_pending();
        reader.0.store(0, Ordering::SeqCst);
        OutboundConnector::begin_shutdown(&node);
        let woke = reader.0.load(Ordering::SeqCst) > 0;
        let error = kind(read_poll(&mut second, &rx));
        let actual_drop = states
            .iter()
            .all(|state| state.drops.load(Ordering::SeqCst) == 1 && state.one_cover());
        OutboundConnector::shutdown(&node).await;
        let joined = node.tasks.is_closed() && node.tasks.is_empty();
        drop(second);
        drop(node);
        drop(upstream);
        drop(states);
        drop(rx);
        drop(tx);
        drop(reader);
        drop(writer);
        let owners_released =
            weak_one.upgrade().is_none() && released(&weak_two, &reader_weak, &writer_weak);
        assert!(
            isolated
                && accepted
                && flushed
                && pending_read
                && woke
                && actual_drop
                && joined
                && owners_released,
            "real child Drop/parent Stop ownership failed: {cipher}"
        );
        assert_eq!(error, Some(io::ErrorKind::ConnectionAborted));
    }
}
