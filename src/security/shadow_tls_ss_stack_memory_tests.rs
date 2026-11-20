//! Synthetic native-TLS + Vole ShadowTLS/SS + official SS server stack.
//! No routing key, socket, listener, official ShadowTLS peer, or HTTP pool credit.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::future::poll_fn;
use shadowsocks::{
    ServerConfig as SsConfig,
    config::ServerType,
    context::Context as SsContext,
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyServerStream},
};
use std::{future::Future, sync::Mutex, task::Waker, time::Duration};
use tokio::{
    io::{AsyncReadExt, DuplexStream},
    sync::oneshot,
};
#[derive(Default)]
struct Budget {
    left: Option<usize>,
    written: usize,
    target: Option<usize>,
    read_total: usize,
    gated_pending: usize,
    installed: bool,
    first_then_eight: bool,
    waker: Option<Waker>,
    dropped: bool,
}
#[derive(Default)]
struct Watch {
    state: Mutex<Budget>,
}
impl Watch {
    fn arm(&self, bytes: Option<usize>) {
        let mut s = self.state.lock().unwrap();
        s.left = bytes;
        s.target = bytes;
        s.written = 0;
        s.first_then_eight = bytes.is_none();
    }
    fn reached(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.target.is_some_and(|n| s.written == n)
    }
    fn read_total(&self) -> usize {
        self.state.lock().unwrap().read_total
    }
    fn target(&self) -> Option<usize> {
        self.state.lock().unwrap().target
    }
    fn pending_writes(&self) -> usize {
        self.state.lock().unwrap().gated_pending
    }
    fn blocked_since(&self, before: usize) -> bool {
        let s = self.state.lock().unwrap();
        s.target.is_some_and(|n| s.written == n) && s.waker.is_some() && s.gated_pending > before
    }
    fn release(&self) {
        let waker = {
            let mut s = self.state.lock().unwrap();
            s.left = None;
            s.first_then_eight = false;
            s.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
struct Gate {
    raw: DuplexStream,
    watch: Arc<Watch>,
}
impl Gate {
    fn new(raw: DuplexStream, watch: Arc<Watch>) -> Self {
        watch.state.lock().unwrap().installed = true;
        Self { raw, watch }
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        let mut s = self.watch.state.lock().unwrap();
        s.waker.take();
        s.dropped = true;
    }
}
impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let result = Pin::new(&mut self.raw).poll_read(cx, out);
        self.watch.state.lock().unwrap().read_total += out.filled().len() - before;
        result
    }
}
impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let limit = {
            let mut s = self.watch.state.lock().unwrap();
            if s.first_then_eight {
                if bytes.len() < 5 || bytes[..3] != [23, 3, 3] {
                    return Poll::Ready(Err(failed("invalid test record-boundary seam")));
                }
                let target = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]])) + 8;
                s.left = Some(target);
                s.target = Some(target);
                s.first_then_eight = false;
            }
            if s.left == Some(0) {
                s.gated_pending += 1;
                s.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            s.left.unwrap_or(bytes.len()).min(bytes.len())
        };
        let result = Pin::new(&mut self.raw).poll_write(cx, &bytes[..limit]);
        if let Poll::Ready(Ok(count)) = &result {
            let mut s = self.watch.state.lock().unwrap();
            s.written += *count;
            if let Some(left) = &mut s.left {
                *left -= *count;
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}
fn failed(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn peer_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
enum Step {
    Complete(io::Result<usize>),
    Cancelled,
}
#[tokio::test(flavor = "current_thread")]
async fn ss2022_over_authenticated_shadowtls_preserves_partial_cancelled_write_and_idle_read()
-> io::Result<()> {
    let (cover, context, options) = crate::security::shadow_tls_tests::ss_stack_material();
    let client = ShadowTlsClient::new(&context, &options)?;
    let password = options.password.as_bytes().to_vec();
    drop((context, options));
    let method = crate::config::ShadowsocksCipher::Aes128Gcm
        .as_str()
        .parse()
        .map_err(peer_error)?;
    let key = [7_u8; 16];
    let config = Arc::new(
        SsConfig::new(("192.0.2.10", 443), STANDARD.encode(key), method).map_err(peer_error)?,
    );
    let client_config = config.clone();
    let upload = Arc::new([vec![0x41_u8; 65536], vec![0x42; 65536]].concat());
    let reply = Arc::new([vec![0x61_u8; 65536], vec![0x62; 65536]].concat());
    let (client_payload, server_payload) = (upload.clone(), upload.clone());
    let (client_reply, server_reply) = (reply.clone(), reply.clone());
    let client_watch = Arc::new(Watch::default());
    let server_watch = Arc::new(Watch::default());
    let client_weak = Arc::downgrade(&client_watch);
    let server_weak = Arc::downgrade(&server_watch);
    let (write_watch, read_watch) = (client_watch.clone(), server_watch.clone());
    let peer_watch = server_watch.clone();
    let (raw, mut peer) = tokio::io::duplex(73);
    let raw = Gate::new(raw, client_watch.clone());
    let (ready, handshake_done) = oneshot::channel();
    let caller = async move {
        let relay = client.connect(Box::new(raw)).await?;
        handshake_done.await.map_err(peer_error)?;
        let target =
            crate::session::Destination::domain("stack.invalid", 443).map_err(peer_error)?;
        let mut stream =
            crate::outbound::memory_test_ss_stack_stream(relay, &client_config, &target);
        write_watch.arm(Some(7));
        let mut admitted = 0;
        let mut cancelled_write = false;
        let mut write_observation_polls = 0_usize;
        for _ in 0..4 {
            let raw_pending_before = write_watch.pending_writes();
            let mut future = Box::pin(stream.write(&client_payload[admitted..]));
            let step = poll_fn(|cx| {
                write_observation_polls += 1;
                if write_observation_polls > 4096 {
                    return Poll::Ready(Step::Complete(Err(failed(
                        "bounded write observation seam exhausted",
                    ))));
                }
                match Future::poll(future.as_mut(), cx) {
                    Poll::Pending if write_watch.blocked_since(raw_pending_before) => {
                        Poll::Ready(Step::Cancelled)
                    }
                    Poll::Pending => {
                        if write_watch.reached() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                    Poll::Ready(result) => Poll::Ready(Step::Complete(result)),
                }
            })
            .await;
            drop(future);
            match step {
                Step::Cancelled => {
                    cancelled_write = true;
                    break;
                }
                Step::Complete(result) => {
                    let count = result?;
                    if count == 0 || count > client_payload.len() - admitted {
                        return Err(failed("invalid write admission before cancellation seam"));
                    }
                    admitted += count;
                }
            }
        }
        if !cancelled_write || admitted == 0 || !write_watch.reached() {
            return Err(failed(
                "invalid seam: no admitted SS bytes then partial raw write Pending",
            ));
        }
        write_watch.release();
        // Never retry already accepted plaintext after dropping write future.
        stream.write_all(&client_payload[admitted..]).await?;
        stream.flush().await?;
        let mut received = vec![0_u8; client_reply.len()];
        let mut offset = 0;
        let mut cancelled_read = false;
        // One baseline for the WHOLE probe, retained across ready plaintext prefixes.
        let raw_read_before_probe = write_watch.read_total();
        let mut read_observation_polls = 0_usize;
        for _ in 0..16 {
            let mut future = Box::pin(stream.read(&mut received[offset..]));
            let step = poll_fn(|cx| {
                read_observation_polls += 1;
                if read_observation_polls > 4096 {
                    return Poll::Ready(Step::Complete(Err(failed(
                        "bounded read observation seam exhausted",
                    ))));
                }
                match Future::poll(future.as_mut(), cx) {
                    Poll::Pending => {
                        let delta = write_watch.read_total().checked_sub(raw_read_before_probe);
                        let target = read_watch.target();
                        if read_watch.reached() && target.is_some() && delta == target {
                            return Poll::Ready(Step::Cancelled);
                        }
                        if let (Some(delta), Some(target)) = (delta, target)
                            && delta > target
                        {
                            return Poll::Ready(Step::Complete(Err(failed(
                                "raw read observation exceeded peer target",
                            ))));
                        }
                        if read_watch.reached() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                    Poll::Ready(result) => Poll::Ready(Step::Complete(result)),
                }
            })
            .await;
            drop(future);
            match step {
                Step::Cancelled => {
                    cancelled_read = true;
                    break;
                }
                Step::Complete(result) => {
                    let count = result?;
                    if count == 0 || count > received.len() - offset {
                        return Err(failed("invalid read before cancellation seam"));
                    }
                    offset += count;
                    if offset == received.len() {
                        break;
                    }
                }
            }
        }
        if !cancelled_read
            || !read_watch.reached()
            || write_watch.read_total().checked_sub(raw_read_before_probe) != read_watch.target()
            || received[..offset] != client_reply[..offset]
        {
            return Err(failed(
                "invalid seam: no partial second authenticated relay record Pending",
            ));
        }
        read_watch.release();
        stream.read_exact(&mut received[offset..]).await?;
        if received.as_slice() != client_reply.as_slice() {
            return Err(failed("stacked response changed"));
        }
        stream.shutdown().await?;
        if stream.read(&mut [0; 1]).await? != 0 {
            return Err(failed("unexpected response tail"));
        }
        Ok::<_, io::Error>(())
    };
    let responder = async move {
        let seed =
            crate::security::shadow_tls_tests::ss_stack_handshake_seed(&mut peer, cover).await?;
        // Real TLS above; business HMAC uses production Verified in reverse
        // directions. This is NOT an independent official ShadowTLS server.
        let relay = Verified {
            raw: Box::new(Gate::new(peer, peer_watch.clone())),
            record: Record::new(),
            pending: None,
            tx: Mac::new(&password, &seed, b"S"),
            rx: Mac::new(&password, &seed, b"C"),
            ignore: None,
            write: Vec::new(),
            written: 0,
            failed: false,
            closing: None,
            closed: false,
        };
        let mut stream = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            relay,
            method,
            &key,
        );
        ready
            .send(())
            .map_err(|_| failed("caller stopped during cover handshake"))?;
        if stream.handshake().await.map_err(peer_error)?
            != Address::DomainNameAddress("stack.invalid".into(), 443)
        {
            return Err(failed("SS target prelude changed"));
        }
        let mut actual = vec![0_u8; server_payload.len()];
        stream.read_exact(&mut actual).await?;
        if actual.as_slice() != server_payload.as_slice() {
            return Err(failed("SS upload duplicated or changed"));
        }
        // Let one COMPLETE authenticated relay record through, then only 8B of
        // the next. This advances the SS reader as well as partial relay state.
        peer_watch.arm(None);
        stream.write_all(&server_reply).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        if stream.read(&mut [0; 1]).await? != 0 {
            return Err(failed("duplicate SS target or upload tail"));
        }
        Ok::<_, io::Error>(())
    };
    // No spawned task: try_join drops the other future on error; timeout drops
    // both complete future trees. Every IO owner is gone before any assertion.
    let result = tokio::time::timeout(Duration::from_secs(10), async move {
        tokio::try_join!(caller, responder)
    })
    .await;
    let client_state = {
        let s = client_watch.state.lock().unwrap();
        (s.installed, s.dropped, s.waker.is_none())
    };
    let server_state = {
        let s = server_watch.state.lock().unwrap();
        (s.installed, s.dropped, s.waker.is_none())
    };
    let installed_closed =
        (!client_state.0 || client_state.1) && (!server_state.0 || server_state.1);
    let both_installed_dropped =
        client_state.0 && client_state.1 && server_state.0 && server_state.1;
    let released = client_state.2 && server_state.2;
    drop((client_watch, server_watch, config, upload, reply));
    let weak_closed = client_weak.upgrade().is_none() && server_weak.upgrade().is_none();
    if !installed_closed || !released || !weak_closed {
        return Err(io::Error::other(format!(
            "installed stack owners survived cleanup; original: {result:?}"
        )));
    }
    // If TLS failed before the server Gate existed, preserve that real error.
    // Successful transfer still requires BOTH actual Gate installations/drops.
    result.map_err(|_| failed("bounded stacked protocol fixture expired"))??;
    assert!(
        both_installed_dropped,
        "successful stack skipped a Gate installation"
    );
    Ok(())
}
