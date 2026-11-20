//! Obfs parent ownership around a real complete SS2022 stream.
//! Raw IO remains deliberately Pending; no socket, peer or wire acceptance.
use super::super::{address, stream::SsStream};
use super::*;
use crate::config::{Config, ProxyProtocol, ShadowsocksCipher, ShadowsocksOutboundConfig};
use ::shadowsocks::{ServerConfig, config::ServerType, context::Context as SsContext};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct State {
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    polls: usize,
    dropped: bool,
}
struct Raw(Arc<Mutex<State>>);
impl Drop for Raw {
    fn drop(&mut self) {
        let mut state = self.0.lock().unwrap();
        state.dropped = true;
        state.read_waker = None;
        state.write_waker = None;
    }
}
impl AsyncRead for Raw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.polls += 1;
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl AsyncWrite for Raw {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        state.polls += 1;
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.polls += 1;
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        state.polls += 1;
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
#[derive(Default)]
struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn config(cipher: ShadowsocksCipher, tls: bool) -> ShadowsocksOutboundConfig {
    let input = serde_json::json!({
        "proxies": [{
            "name": "obfs", "type": "ss", "server": "192.0.2.10", "port": 8443,
            "cipher": cipher.as_str(), "password": STANDARD.encode(vec![7; cipher.key_len()]),
            "plugin": "obfs", "plugin-opts": {"mode": if tls { "tls" } else { "http" }, "host": "cover.invalid"}
        }],
        "rules": ["MATCH,obfs"]
    });
    let parsed = Config::parse_yaml(&serde_json::to_vec(&input).unwrap()).unwrap();
    let ProxyProtocol::Shadowsocks(config) = &parsed.proxies[0].protocol else {
        panic!("real SS configuration expected")
    };
    config.clone()
}
fn owner(config: &ShadowsocksOutboundConfig) -> Owner {
    Owner::new(
        config.plugin.as_ref().unwrap(),
        &SecurityContext::new(),
        0,
        16384,
        config.port,
    )
    .unwrap()
}
fn unbound(config: &ShadowsocksOutboundConfig) -> (BoxStream, Arc<Mutex<State>>) {
    let server = ServerConfig::new(
        (config.address.clone(), config.port),
        config.password.clone(),
        config.cipher.as_str().parse().unwrap(),
    )
    .unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let stream = SsStream::new(
        SsContext::new_shared(ServerType::Local),
        Box::new(Raw(state.clone())),
        &server,
        address(&Destination::domain("origin.invalid", 443).unwrap()),
    );
    (Box::new(stream), state)
}
fn ciphers() -> [ShadowsocksCipher; 3] {
    [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ]
}

#[tokio::test(flavor = "current_thread")]
async fn obfs_owned_complete_ss_stream_stop_wakes_independent_pending_operations() {
    let mut observations = Vec::new();
    for cipher in ciphers() {
        for tls in [false, true] {
            for operation in ["write", "flush", "shutdown"] {
                let config = config(cipher, tls);
                let owner = owner(&config);
                let (stream, state) = unbound(&config);
                let weak_state = Arc::downgrade(&state);
                let mut stream = owner.bind_stream(stream);
                let a = Arc::new(Count::default());
                let b = Arc::new(Count::default());
                let weak_a = Arc::downgrade(&a);
                let weak_b = Arc::downgrade(&b);
                let wa = Waker::from(a.clone());
                let wb = Waker::from(b.clone());
                let payload = b"accepted-first-ss-payload";
                // Real SsStream accepts one bounded first frame while retaining
                // the actual encrypted prefix across underlying write Pending.
                let primed = matches!(Pin::new(&mut *stream).poll_write(&mut Context::from_waker(&wb), payload), Poll::Ready(Ok(n)) if n == payload.len());
                let read_pending = Pin::new(&mut *stream)
                    .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0]))
                    .is_pending();
                let writer_pending = match operation {
                    "write" => Pin::new(&mut *stream)
                        .poll_write(&mut Context::from_waker(&wb), b"next")
                        .is_pending(),
                    "flush" => Pin::new(&mut *stream)
                        .poll_flush(&mut Context::from_waker(&wb))
                        .is_pending(),
                    "shutdown" => Pin::new(&mut *stream)
                        .poll_shutdown(&mut Context::from_waker(&wb))
                        .is_pending(),
                    _ => unreachable!(),
                };
                let raw_both = {
                    let state = state.lock().unwrap();
                    state.read_waker.is_some() && state.write_waker.is_some()
                };
                let before_a = a.0.load(Ordering::SeqCst);
                let before_b = b.0.load(Ordering::SeqCst);
                owner.begin_shutdown();
                // Observe cancellation before explicit repoll/Drop can wake it.
                let woke_a = a.0.load(Ordering::SeqCst) > before_a;
                let woke_b = b.0.load(Ordering::SeqCst) > before_b;
                let read_aborted = matches!(Pin::new(&mut *stream).poll_read(
                    &mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0]),
                ), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
                let write_aborted = match operation {
                    "write" => {
                        matches!(Pin::new(&mut *stream).poll_write(&mut Context::from_waker(&wb), b"next"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted)
                    }
                    "flush" => {
                        matches!(Pin::new(&mut *stream).poll_flush(&mut Context::from_waker(&wb)), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted)
                    }
                    "shutdown" => {
                        matches!(Pin::new(&mut *stream).poll_shutdown(&mut Context::from_waker(&wb)), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted)
                    }
                    _ => unreachable!(),
                };
                let parent_stopped = owner.cancel.is_cancelled() && !owner.permits_http_tcp_reuse();
                // Obfs has no plugin driver. This is the real tracker barrier,
                // not a claim that cancelling alone released idle external IO.
                owner.shutdown().await;
                drop(stream);
                drop(owner);
                drop(wa);
                drop(wb);
                drop(a);
                drop(b);
                let raw_released = {
                    let state = state.lock().unwrap();
                    state.dropped && state.read_waker.is_none() && state.write_waker.is_none()
                };
                drop(state);
                assert!(
                    raw_released
                        && weak_state.upgrade().is_none()
                        && weak_a.upgrade().is_none()
                        && weak_b.upgrade().is_none()
                );
                observations.push((
                    cipher,
                    tls,
                    operation,
                    primed && read_pending && writer_pending && raw_both,
                    parent_stopped,
                    woke_a && woke_b,
                    read_aborted && write_aborted,
                ));
            }
        }
    }
    assert_eq!(observations.len(), 18);
    assert!(
        observations
            .iter()
            .all(|(_, _, _, pending, parent, wakes, aborted)| *pending
                && *parent
                && *wakes
                && *aborted),
        "complete SS owner observations: {observations:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn obfs_owned_stop_before_bind_rejects_complete_ss_without_touching_raw() {
    let mut observations = Vec::new();
    for cipher in ciphers() {
        for tls in [false, true] {
            let config = config(cipher, tls);
            let owner = owner(&config);
            let (stream, state) = unbound(&config);
            let weak_state = Arc::downgrade(&state);
            owner.begin_shutdown();
            // Production binds the complete SsStream after open. An already
            // cancelled parent must still bind a cancelled child here.
            let mut stream = owner.bind_stream(stream);
            let a = Arc::new(Count::default());
            let wa = Waker::from(a.clone());
            let read_aborted = matches!(Pin::new(&mut *stream).poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0])), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            let write_aborted = matches!(Pin::new(&mut *stream).poll_write(&mut Context::from_waker(&wa), b"must-not-enter-ss"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            let flush_aborted = matches!(Pin::new(&mut *stream).poll_flush(&mut Context::from_waker(&wa)), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            let shutdown_aborted = matches!(Pin::new(&mut *stream).poll_shutdown(&mut Context::from_waker(&wa)), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            let untouched_and_released = {
                let state = state.lock().unwrap();
                state.polls == 0 && state.dropped
            };
            owner.shutdown().await;
            drop(stream);
            drop(owner);
            drop(wa);
            drop(a);
            assert!(state.lock().unwrap().dropped);
            drop(state);
            assert!(weak_state.upgrade().is_none());
            observations.push((
                cipher,
                tls,
                read_aborted && write_aborted && flush_aborted && shutdown_aborted,
                untouched_and_released,
            ));
        }
    }
    assert_eq!(observations.len(), 6);
    assert!(
        observations
            .iter()
            .all(|(_, _, aborted, untouched)| *aborted && *untouched),
        "post-Stop bind observations: {observations:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn obfs_owned_child_drop_preserves_parent_and_sibling_until_parent_stop() {
    let mut observations = Vec::new();
    for cipher in ciphers() {
        for tls in [false, true] {
            let config = config(cipher, tls);
            let owner = owner(&config);
            let (first, first_state) = unbound(&config);
            let (second, second_state) = unbound(&config);
            let first_weak = Arc::downgrade(&first_state);
            let second_weak = Arc::downgrade(&second_state);
            let first = owner.bind_stream(first);
            let mut second = owner.bind_stream(second);
            drop(first);
            let first_dropped_without_io = {
                let state = first_state.lock().unwrap();
                state.dropped && state.polls == 0
            };
            let parent_open = !owner.cancel.is_cancelled() && !*owner.closed.lock().unwrap();
            let a = Arc::new(Count::default());
            let wa = Waker::from(a.clone());
            let payload = b"sibling-first-ss-payload";
            let sibling_accepts = matches!(Pin::new(&mut *second).poll_write(&mut Context::from_waker(&wa), payload), Poll::Ready(Ok(n)) if n == payload.len());
            let sibling_pending = Pin::new(&mut *second)
                .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0]))
                .is_pending();
            let before = a.0.load(Ordering::SeqCst);
            owner.begin_shutdown();
            let woke = a.0.load(Ordering::SeqCst) > before;
            let aborted = matches!(Pin::new(&mut *second).poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0])), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            owner.shutdown().await;
            drop(second);
            drop(owner);
            drop(wa);
            drop(a);
            assert!(first_state.lock().unwrap().dropped && second_state.lock().unwrap().dropped);
            drop(first_state);
            drop(second_state);
            assert!(first_weak.upgrade().is_none() && second_weak.upgrade().is_none());
            observations.push((
                cipher,
                tls,
                first_dropped_without_io && parent_open && sibling_accepts && sibling_pending,
                woke && aborted,
            ));
        }
    }
    assert_eq!(observations.len(), 6);
    assert!(
        observations
            .iter()
            .all(|(_, _, independent, stopped)| *independent && *stopped),
        "child/sibling SS observations: {observations:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn obfs_owned_existing_fanout_control_handles_complete_ss_pending_fixture() {
    let config = config(ShadowsocksCipher::Aes128Gcm, false);
    let owner = owner(&config);
    let (stream, state) = unbound(&config);
    let weak_state = Arc::downgrade(&state);
    // Existing production fanout only: this control checks the complete-SS
    // fixture, not Obfs Owner.bind or the desired static qualification.
    let mut stream: BoxStream = Box::new(ShadowTlsOwned::new(stream, owner.cancel.child_token()));
    let a = Arc::new(Count::default());
    let b = Arc::new(Count::default());
    let weak_a = Arc::downgrade(&a);
    let weak_b = Arc::downgrade(&b);
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let payload = b"accepted-first-ss-payload";
    let primed = matches!(Pin::new(&mut *stream).poll_write(&mut Context::from_waker(&wb), payload), Poll::Ready(Ok(n)) if n == payload.len());
    let read_pending = Pin::new(&mut *stream)
        .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0]))
        .is_pending();
    let write_pending = Pin::new(&mut *stream)
        .poll_write(&mut Context::from_waker(&wb), b"next")
        .is_pending();
    let both_registered = {
        let state = state.lock().unwrap();
        state.read_waker.is_some() && state.write_waker.is_some()
    };
    let before_a = a.0.load(Ordering::SeqCst);
    let before_b = b.0.load(Ordering::SeqCst);
    owner.begin_shutdown();
    let woke_a = a.0.load(Ordering::SeqCst) > before_a;
    let woke_b = b.0.load(Ordering::SeqCst) > before_b;
    let read_aborted = matches!(Pin::new(&mut *stream).poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0])), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
    let write_aborted = matches!(Pin::new(&mut *stream).poll_write(&mut Context::from_waker(&wb), b"next"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
    owner.shutdown().await;
    drop(stream);
    drop(owner);
    drop(wa);
    drop(wb);
    drop(a);
    drop(b);
    let released = {
        let state = state.lock().unwrap();
        state.dropped && state.read_waker.is_none() && state.write_waker.is_none()
    };
    drop(state);
    assert!(
        released
            && weak_state.upgrade().is_none()
            && weak_a.upgrade().is_none()
            && weak_b.upgrade().is_none()
    );
    assert!(
        primed
            && read_pending
            && write_pending
            && both_registered
            && woke_a
            && woke_b
            && read_aborted
            && write_aborted,
        "existing fanout fixture control: primed={primed}, pending={read_pending}/{write_pending}, raw={both_registered}, wakes={woke_a}/{woke_b}, aborted={read_aborted}/{write_aborted}"
    );
}
