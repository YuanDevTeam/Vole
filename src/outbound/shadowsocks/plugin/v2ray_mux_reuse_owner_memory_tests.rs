//! Complete SS2022 owner controls for plain standard-WS v2ray-plugin mux.
//! Pending raw IO isolates binding/cancellation; no WS/mux wire acceptance,
//! handshake, socket, resolver or pressure result is claimed by these tests.
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
impl Raw {
    fn pending_write(&self, cx: &mut Context<'_>) {
        let mut state = self.0.lock().unwrap();
        state.polls += 1;
        state.write_waker = Some(cx.waker().clone());
    }
}
impl AsyncWrite for Raw {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        self.pending_write(cx);
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.pending_write(cx);
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.pending_write(cx);
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
fn ciphers() -> [ShadowsocksCipher; 3] {
    [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ]
}
fn config(cipher: ShadowsocksCipher) -> ShadowsocksOutboundConfig {
    let input = serde_json::json!({
        "proxies": [{"name":"mux", "type":"ss", "server":"192.0.2.10", "port":8443,
            "cipher":cipher.as_str(), "password":STANDARD.encode(vec![7; cipher.key_len()]),
            "plugin":"v2ray-plugin", "plugin-opts":{"mode":"websocket", "host":"cover.invalid",
                "path":"/mux", "mux":true, "tls":false}}],
        "rules":["MATCH,mux"]
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
        16_384,
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
fn write_operation(stream: &mut BoxStream, waker: &Waker, operation: &str) -> Poll<io::Result<()>> {
    let mut cx = Context::from_waker(waker);
    match operation {
        "write" => Pin::new(&mut **stream)
            .poll_write(&mut cx, b"next")
            .map(|result| result.map(|_| ())),
        "flush" => Pin::new(&mut **stream).poll_flush(&mut cx),
        "shutdown" => Pin::new(&mut **stream).poll_shutdown(&mut cx),
        _ => unreachable!(),
    }
}
#[derive(Debug)]
struct StopObservation {
    parent_stopped: bool,
    woke_reader: bool,
    woke_writer: bool,
    read_aborted: bool,
    write_aborted: bool,
    raw_not_repolled: bool,
    released_by_cancel_poll: bool,
}
impl StopObservation {
    fn passed(&self) -> bool {
        self.parent_stopped
            && self.woke_reader
            && self.woke_writer
            && self.read_aborted
            && self.write_aborted
            && self.raw_not_repolled
            && self.released_by_cancel_poll
    }
}
async fn pending_stop(
    cipher: ShadowsocksCipher,
    operation: &str,
    control: bool,
) -> StopObservation {
    let config = config(cipher);
    let owner = owner(&config);
    let (stream, state) = unbound(&config);
    let weak_state = Arc::downgrade(&state);
    let mut stream = if control {
        // Existing production wrapper only: validates this real SsStream fixture
        // without pretending Owner.bind already accepts the new factory.
        Box::new(ShadowTlsOwned::new(stream, owner.cancel.child_token())) as BoxStream
    } else {
        owner.bind_stream(stream)
    };
    let a = Arc::new(Count::default());
    let b = Arc::new(Count::default());
    let weak_a = Arc::downgrade(&a);
    let weak_b = Arc::downgrade(&b);
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let payload = b"accepted-first-ss-payload";
    let primed = matches!(Pin::new(&mut *stream).poll_write(&mut Context::from_waker(&wb), payload),
        Poll::Ready(Ok(n)) if n == payload.len());
    let read_pending = Pin::new(&mut *stream)
        .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0]))
        .is_pending();
    let write_pending = write_operation(&mut stream, &wb, operation).is_pending();
    let (raw_both, raw_polls) = {
        let state = state.lock().unwrap();
        (
            state.read_waker.is_some() && state.write_waker.is_some(),
            state.polls,
        )
    };
    let before_a = a.0.load(Ordering::SeqCst);
    let before_b = b.0.load(Ordering::SeqCst);
    owner.begin_shutdown();
    let woke_reader = a.0.load(Ordering::SeqCst) > before_a;
    let woke_writer = b.0.load(Ordering::SeqCst) > before_b;
    let read_aborted = matches!(Pin::new(&mut *stream).poll_read(
        &mut Context::from_waker(&wa), &mut ReadBuf::new(&mut [0])),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
    let write_aborted = matches!(write_operation(&mut stream, &wb, operation),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
    let (raw_not_repolled, released_by_cancel_poll) = {
        let state = state.lock().unwrap();
        (state.polls == raw_polls, state.dropped)
    };
    let parent_stopped = owner.cancel.is_cancelled() && !owner.permits_http_tcp_reuse();
    // Non-Gost WS has no plugin driver. The real tracker barrier does not
    // substitute for the separately observed actual IO Drop above.
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
        primed && read_pending && write_pending && raw_both,
        "real SS fixture premise: {cipher:?}/{operation} primed={primed} pending={read_pending}/{write_pending} raw={raw_both}"
    );
    StopObservation {
        parent_stopped,
        woke_reader,
        woke_writer,
        read_aborted,
        write_aborted,
        raw_not_repolled,
        released_by_cancel_poll,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_existing_fanout_control_handles_complete_ss_pending_fixture() {
    let observed = pending_stop(ShadowsocksCipher::Aes128Gcm, "write", true).await;
    assert!(
        observed.passed(),
        "existing complete-stream fanout control: {observed:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_complete_ss_stop_wakes_independent_pending_operations() {
    let mut observed = Vec::new();
    for cipher in ciphers() {
        for operation in ["write", "flush", "shutdown"] {
            observed.push((
                cipher,
                operation,
                pending_stop(cipher, operation, false).await,
            ));
        }
    }
    assert_eq!(observed.len(), 9);
    assert!(
        observed.iter().all(|(_, _, row)| row.passed()),
        "actual complete SS v2ray mux owner observations: {observed:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_stop_before_bind_rejects_complete_ss_without_touching_raw() {
    let mut observed = Vec::new();
    for cipher in ciphers() {
        let config = config(cipher);
        let owner = owner(&config);
        let (stream, state) = unbound(&config);
        let weak_state = Arc::downgrade(&state);
        owner.begin_shutdown();
        let mut stream = owner.bind_stream(stream);
        let count = Arc::new(Count::default());
        let weak_count = Arc::downgrade(&count);
        let waker = Waker::from(count.clone());
        let read_aborted = matches!(Pin::new(&mut *stream).poll_read(
            &mut Context::from_waker(&waker), &mut ReadBuf::new(&mut [0])),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
        let write_aborted = ["write", "flush", "shutdown"].map(|operation| {
            matches!(write_operation(&mut stream, &waker, operation),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted)
        });
        let all_write_aborted = write_aborted.into_iter().all(|aborted| aborted);
        let untouched_and_released = {
            let state = state.lock().unwrap();
            state.polls == 0 && state.dropped
        };
        owner.shutdown().await;
        drop(stream);
        drop(owner);
        drop(waker);
        drop(count);
        assert!(state.lock().unwrap().dropped);
        drop(state);
        assert!(weak_state.upgrade().is_none() && weak_count.upgrade().is_none());
        observed.push((
            cipher,
            read_aborted && all_write_aborted,
            untouched_and_released,
        ));
    }
    assert_eq!(observed.len(), 3);
    assert!(
        observed
            .iter()
            .all(|(_, aborted, untouched)| *aborted && *untouched),
        "Stop-before-bind complete SS observations: {observed:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_child_drop_preserves_parent_and_sibling_until_parent_stop() {
    let mut observed = Vec::new();
    for cipher in ciphers() {
        let config = config(cipher);
        let owner = owner(&config);
        let (first, first_state) = unbound(&config);
        let (second, second_state) = unbound(&config);
        let first_weak = Arc::downgrade(&first_state);
        let second_weak = Arc::downgrade(&second_state);
        let first = owner.bind_stream(first);
        let mut second = owner.bind_stream(second);
        drop(first);
        let first_closed = {
            let state = first_state.lock().unwrap();
            state.dropped && state.polls == 0
        };
        let parent_open = !owner.cancel.is_cancelled() && !*owner.closed.lock().unwrap();
        let count = Arc::new(Count::default());
        let weak_count = Arc::downgrade(&count);
        let waker = Waker::from(count.clone());
        let payload = b"sibling-first-ss-payload";
        let accepts = matches!(Pin::new(&mut *second).poll_write(&mut Context::from_waker(&waker), payload),
            Poll::Ready(Ok(n)) if n == payload.len());
        let pending = Pin::new(&mut *second)
            .poll_read(
                &mut Context::from_waker(&waker),
                &mut ReadBuf::new(&mut [0]),
            )
            .is_pending();
        let before = count.0.load(Ordering::SeqCst);
        let raw_before = second_state.lock().unwrap().polls;
        owner.begin_shutdown();
        let woke = count.0.load(Ordering::SeqCst) > before;
        let aborted = matches!(Pin::new(&mut *second).poll_read(&mut Context::from_waker(&waker),
            &mut ReadBuf::new(&mut [0])), Poll::Ready(Err(error))
                if error.kind() == io::ErrorKind::ConnectionAborted);
        let released_without_repoll = {
            let state = second_state.lock().unwrap();
            state.dropped && state.polls == raw_before
        };
        owner.shutdown().await;
        drop(second);
        drop(owner);
        drop(waker);
        drop(count);
        assert!(first_state.lock().unwrap().dropped && second_state.lock().unwrap().dropped);
        drop(first_state);
        drop(second_state);
        assert!(
            first_weak.upgrade().is_none()
                && second_weak.upgrade().is_none()
                && weak_count.upgrade().is_none()
        );
        observed.push((
            cipher,
            first_closed && parent_open && accepts && pending,
            woke && aborted && released_without_repoll,
        ));
    }
    assert_eq!(observed.len(), 3);
    assert!(
        observed
            .iter()
            .all(|(_, independent, stopped)| *independent && *stopped),
        "complete SS child/sibling observations: {observed:?}"
    );
}
