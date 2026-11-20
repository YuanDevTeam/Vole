//! Actual Core serve_h2 receive settings and exhausted-connection controls.
//! Duplex only: no listener, TLS acceptance, benchmark qualification or retry.
use super::*;
use futures_util::future::poll_fn;
use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::time::{Instant, timeout_at};

struct CountedIo {
    inner: DuplexStream,
    live: Arc<AtomicUsize>,
    writes: Option<Arc<Mutex<WireWrites>>>,
    data: Option<Arc<ClientData>>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DataSnapshot {
    bytes: [usize; 2],
    end_streams: u8,
}
struct DataFrames {
    preface: usize,
    head: [u8; 9],
    head_used: usize,
    remaining: usize,
    data_stream: Option<usize>,
    data_length: usize,
    data_end: bool,
    snapshot: DataSnapshot,
    error: Option<&'static str>,
}
impl DataFrames {
    fn new() -> Self {
        Self {
            preface: 0,
            head: [0; 9],
            head_used: 0,
            remaining: 0,
            data_stream: None,
            data_length: 0,
            data_end: false,
            snapshot: DataSnapshot::default(),
            error: None,
        }
    }
    fn record(&mut self, mut bytes: &[u8]) {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        while !bytes.is_empty() && self.error.is_none() {
            if self.preface < PREFACE.len() {
                let count = bytes.len().min(PREFACE.len() - self.preface);
                if bytes[..count] != PREFACE[self.preface..self.preface + count] {
                    self.error = Some("unexpected synthetic client preface");
                    return;
                }
                self.preface += count;
                bytes = &bytes[count..];
                continue;
            }
            if self.head_used < self.head.len() {
                let count = bytes.len().min(self.head.len() - self.head_used);
                self.head[self.head_used..self.head_used + count].copy_from_slice(&bytes[..count]);
                self.head_used += count;
                bytes = &bytes[count..];
                if self.head_used != self.head.len() {
                    continue;
                }
                self.remaining =
                    u32::from_be_bytes([0, self.head[0], self.head[1], self.head[2]]) as usize;
                if self.remaining > 16 * 1024 {
                    self.error = Some("synthetic client exceeded the actual peer frame bound");
                    return;
                }
                self.data_stream = None;
                self.data_length = 0;
                self.data_end = false;
                if self.head[3] == 0 {
                    let stream =
                        u32::from_be_bytes(self.head[5..9].try_into().unwrap()) & 0x7fff_ffff;
                    self.data_stream = match stream {
                        1 => Some(0),
                        3 => Some(1),
                        _ => {
                            self.error = Some("unexpected synthetic DATA stream");
                            return;
                        }
                    };
                    if self.head[4] & 8 != 0 {
                        self.error = Some("unexpected synthetic DATA padding");
                        return;
                    }
                    self.data_length = self.remaining;
                    self.data_end = self.head[4] & 1 != 0;
                }
            }
            let count = bytes.len().min(self.remaining);
            self.remaining -= count;
            bytes = &bytes[count..];
            if self.remaining != 0 {
                continue;
            }
            if let Some(stream) = self.data_stream {
                if self.snapshot.end_streams & (1 << stream) != 0 {
                    self.error = Some("synthetic DATA after original END_STREAM");
                    return;
                }
                let Some(total) = self.snapshot.bytes[stream].checked_add(self.data_length) else {
                    self.error = Some("synthetic DATA counter overflow");
                    return;
                };
                if total > 32 * 1024 {
                    self.error = Some("synthetic original body exceeded its frozen length");
                    return;
                }
                self.snapshot.bytes[stream] = total;
                if self.data_end {
                    self.snapshot.end_streams |= 1 << stream;
                }
            }
            self.head_used = 0;
        }
    }
    fn snapshot(&self) -> io::Result<DataSnapshot> {
        self.error
            .map_or(Ok(self.snapshot), |message| Err(failed(message)))
    }
}
struct ClientData {
    frames: Mutex<DataFrames>,
    changed: tokio::sync::Notify,
}
impl ClientData {
    fn new() -> Self {
        Self {
            frames: Mutex::new(DataFrames::new()),
            changed: tokio::sync::Notify::new(),
        }
    }
    fn record(&self, bytes: &[u8]) {
        self.frames.lock().unwrap().record(bytes);
        self.changed.notify_one();
    }
    async fn complete(&self) -> io::Result<DataSnapshot> {
        loop {
            let changed = self.changed.notified();
            let actual = self.frames.lock().unwrap().snapshot()?;
            if actual
                == (DataSnapshot {
                    bytes: [32 * 1024; 2],
                    end_streams: 3,
                })
            {
                return Ok(actual);
            }
            changed.await;
        }
    }
}
struct WireWrites {
    bytes: Vec<u8>,
    overflow: bool,
}
impl WireWrites {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4096),
            overflow: false,
        }
    }
    fn updates(&self) -> io::Result<(usize, u32)> {
        if self.overflow {
            return Err(failed("bounded synthetic wire evidence overflow"));
        }
        let mut offset = 0;
        let (mut count, mut total) = (0, 0);
        while offset + 9 <= self.bytes.len() {
            let head = &self.bytes[offset..offset + 9];
            let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let end = offset + 9 + length;
            if end > self.bytes.len() {
                return Err(failed("partial synthetic wire evidence"));
            }
            let stream = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff;
            if head[3] == 8 && stream == 0 && length == 4 {
                count += 1;
                total += u32::from_be_bytes(self.bytes[offset + 9..end].try_into().unwrap())
                    & 0x7fff_ffff;
            }
            offset = end;
        }
        if offset != self.bytes.len() {
            return Err(failed("partial synthetic frame header"));
        }
        Ok((count, total))
    }
}
impl CountedIo {
    fn new(inner: DuplexStream, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::AcqRel);
        Self {
            inner,
            live: live.clone(),
            writes: None,
            data: None,
        }
    }
    fn record_write(&self, bytes: &[u8]) {
        if let Some(evidence) = &self.writes {
            let mut evidence = evidence.lock().unwrap();
            let record = bytes.len().min(4096 - evidence.bytes.len());
            evidence.bytes.extend_from_slice(&bytes[..record]);
            evidence.overflow |= record != bytes.len();
        }
        if let Some(data) = &self.data {
            data.record(bytes);
        }
    }
}
impl Drop for CountedIo {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}
impl AsyncRead for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(written)) = result {
            self.record_write(&bytes[..written]);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, buffers);
        if let Poll::Ready(Ok(written)) = result {
            let mut remaining = written;
            for buffer in buffers {
                let count = remaining.min(buffer.len());
                self.record_write(&buffer[..count]);
                remaining -= count;
                if remaining == 0 {
                    break;
                }
            }
            if remaining != 0 {
                return Poll::Ready(Err(failed("invalid vectored write length")));
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn failed(message: &'static str) -> io::Error {
    io::Error::other(message)
}
async fn joined<T>(mut owner: tokio::task::JoinHandle<T>) -> Result<T, String> {
    match timeout(Duration::from_secs(2), &mut owner).await {
        Ok(result) => result.map_err(|failure| failure.to_string()),
        Err(_) => {
            owner.abort();
            let _ = owner.await;
            Err("owner timed out and was actually aborted/joined".into())
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn counted_client_data_tracks_only_actual_vectored_short_write_prefixes() {
    let live = Arc::new(AtomicUsize::new(0));
    let data = Arc::new(ClientData::new());
    let (client, mut peer) = tokio::io::duplex(30);
    let mut client = CountedIo::new(client, &live);
    client.data = Some(data.clone());
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let frame = raw_h2_frame(0, 1, 1, &[7; 17]);
    let slices: [&[u8]; 3] = [preface, &frame[..9], &frame[9..]];
    let total: usize = slices.iter().map(|slice| slice.len()).sum();
    let result = timeout(Duration::from_secs(2), async {
        let mut offset = 0;
        let mut saw_short = false;
        let mut premature = false;
        while offset < total {
            let mut skipped = offset;
            let mut buffers = Vec::with_capacity(3);
            for slice in slices {
                let count = skipped.min(slice.len());
                skipped -= count;
                if count != slice.len() {
                    buffers.push(IoSlice::new(&slice[count..]));
                }
            }
            let written = client.write_vectored(&buffers).await?;
            if written == 0 {
                return Err(failed("synthetic vectored write made no progress"));
            }
            saw_short |= written < total - offset;
            offset += written;
            // Drain only bytes the real IO accepted, including short prefixes.
            let mut drained = vec![0; written];
            peer.read_exact(&mut drained).await?;
            let snapshot = data.frames.lock().unwrap().snapshot()?;
            if offset < total && snapshot.bytes[0] != 0 {
                premature = true;
            }
        }
        Ok::<_, io::Error>((
            saw_short,
            premature,
            data.frames.lock().unwrap().snapshot()?,
        ))
    })
    .await;
    drop(client);
    drop(peer);
    assert_eq!(live.load(Ordering::Acquire), 0);
    let (short, premature, actual) = result.unwrap().unwrap();
    assert!(short && !premature);
    assert_eq!(
        actual,
        DataSnapshot {
            bytes: [17, 0],
            end_streams: 1
        }
    );
}
#[derive(Debug, Default)]
struct Advertised {
    stream: Option<u32>,
    concurrent: Option<u32>,
    frame: Option<u32>,
}
async fn read_advertised(client: &mut CountedIo) -> io::Result<Advertised> {
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await?;
    client.write_all(&raw_h2_frame(4, 0, 0, &[])).await?;
    client.flush().await?;
    let mut actual = Advertised::default();
    for _ in 0..16 {
        let mut head = [0u8; 9];
        client.read_exact(&mut head).await?;
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        if length > 16 * 1024 {
            return Err(failed("unexpected initial frame length"));
        }
        let stream = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff;
        let mut payload = vec![0; length];
        client.read_exact(&mut payload).await?;
        if head[3] == 4 && head[4] & 1 == 0 && stream == 0 {
            if !length.is_multiple_of(6) {
                return Err(failed("invalid real SETTINGS payload"));
            }
            for setting in payload.chunks_exact(6) {
                let id = u16::from_be_bytes(setting[..2].try_into().unwrap());
                let value = u32::from_be_bytes(setting[2..].try_into().unwrap());
                match id {
                    3 => actual.concurrent = Some(value),
                    4 => actual.stream = Some(value),
                    5 => actual.frame = Some(value),
                    _ => {}
                }
            }
        }
        if actual.stream.is_some() {
            return Ok(actual);
        }
    }
    Err(failed(
        "actual server did not advertise bounded receive credit",
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn actual_serve_h2_advertises_64k_stream_without_requiring_initial_connection_update() {
    let (context, origin) = prepared(true);
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let live = Arc::new(AtomicUsize::new(0));
    let (client, server) = tokio::io::duplex(8192);
    let mut client = CountedIo::new(client, &live);
    let mut server = CountedIo::new(server, &live);
    let owner = tokio::spawn(async move { context.serve_h2(&mut server, session(), cancel).await });
    let result = timeout(Duration::from_secs(2), read_advertised(&mut client)).await;
    stop.cancel();
    drop(client);
    let core = joined(owner).await;
    origin.join().await;
    // All failure/timeout paths have dropped and actually joined their IO owner.
    assert!(core.as_ref().is_ok_and(|result| result.is_ok()), "{core:?}");
    assert_eq!(live.load(Ordering::Acquire), 0);
    let actual = result
        .expect("real server wire observation timed out")
        .unwrap();
    assert_eq!(actual.stream, Some(65_536));
    assert_eq!(actual.concurrent, Some(8));
    assert_eq!(actual.frame, Some(16_384));
}

struct PendingPlan {
    live: Arc<AtomicUsize>,
}
impl Drop for PendingPlan {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}
struct HeldDispatcher {
    live: Arc<AtomicUsize>,
    entered: AtomicUsize,
    changed: tokio::sync::Notify,
    release: CancellationToken,
    physical_calls: AtomicUsize,
}
impl HeldDispatcher {
    async fn wait_for(&self, expected: usize) {
        while self.entered.load(Ordering::Acquire) < expected {
            self.changed.notified().await;
        }
    }
}
#[async_trait]
impl Dispatcher for HeldDispatcher {
    async fn prepare_http_tcp(
        &self,
        _: StreamSession,
    ) -> Result<Option<Box<dyn crate::dispatch::HttpTcpPlan>>, DispatchError> {
        self.live.fetch_add(1, Ordering::AcqRel);
        let _owner = PendingPlan {
            live: self.live.clone(),
        };
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_one();
        self.release.cancelled().await;
        Err(DispatchError::NotAllowed)
    }
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        self.physical_calls.fetch_add(1, Ordering::AcqRel);
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.physical_calls.fetch_add(1, Ordering::AcqRel);
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn actual_serve_h2_shared_64k_connection_credit_still_times_out_at_original_end() {
    let (base, origin) = prepared(true);
    let held = Arc::new(HeldDispatcher {
        live: Arc::new(AtomicUsize::new(0)),
        entered: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        release: CancellationToken::new(),
        physical_calls: AtomicUsize::new(0),
    });
    let context = HttpContext::new(base.policy.clone(), held.clone(), base.security.clone());
    let start = Instant::now();
    let active_end = start + Duration::from_secs(60);
    // Create the actual Core owner at the original tail slot, avoiding its
    // unrelated 30s idle timer during this controlled one-slot experiment.
    tokio::time::advance(Duration::from_nanos(59_999_000_000)).await;
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let live = Arc::new(AtomicUsize::new(0));
    let (client, server) = tokio::io::duplex(256 * 1024);
    let mut client = CountedIo::new(client, &live);
    let data_evidence = Arc::new(ClientData::new());
    client.data = Some(data_evidence.clone());
    let mut server = CountedIo::new(server, &live);
    let wire_evidence = Arc::new(Mutex::new(WireWrites::new()));
    server.writes = Some(wire_evidence.clone());
    let owner = tokio::spawn(async move { context.serve_h2(&mut server, session(), cancel).await });
    let mut driver = None;
    let observed = timeout_at(start + Duration::from_secs(61), async {
        let (mut sender, mut connection) = wire::client::handshake(client)
            .await
            .map_err(|_| failed("client handshake"))?;
        let mut ping = connection
            .ping_pong()
            .ok_or_else(|| failed("client PING handle"))?;
        driver = Some(tokio::spawn(connection));
        ping.ping(wire::Ping::opaque())
            .await
            .map_err(|_| failed("initial real SETTINGS/PING barrier"))?;
        let mut replies = Vec::with_capacity(3);
        let mut writers = Vec::with_capacity(3);
        let mut submitted = 0usize;
        let mut second_grants = [0usize; 2];
        let mut second_grant_count = 0;
        for sequence in 0..2 {
            sender = sender
                .ready()
                .await
                .map_err(|_| failed("original request ready"))?;
            let (reply, mut writer) = sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri(format!("https://a.test/connection-credit/{sequence}"))
                        .header("content-length", 32 * 1024)
                        .body(())
                        .unwrap(),
                    false,
                )
                .map_err(|_| failed("original request headers"))?;
            held.wait_for(sequence + 1).await;
            let mut offset = 0;
            while offset < 32 * 1024 {
                if Instant::now() >= active_end {
                    return Err(failed("prefill crossed original active boundary"));
                }
                writer.reserve_capacity(32 * 1024 - offset);
                let grant = timeout_at(active_end, poll_fn(|cx| writer.poll_capacity(cx)))
                    .await
                    .map_err(|_| failed("prefill capacity deadline"))?
                    .ok_or_else(|| failed("prefill stream closed"))?
                    .map_err(|_| failed("prefill capacity error"))?;
                if grant == 0 {
                    continue;
                }
                if sequence == 1 {
                    if second_grant_count == second_grants.len() {
                        return Err(failed("unexpected second-body grant count"));
                    }
                    second_grants[second_grant_count] = grant;
                    second_grant_count += 1;
                }
                let count = grant.min(32 * 1024 - offset);
                offset += count;
                writer
                    .send_data(
                        Bytes::from(vec![7 + sequence as u8; count]),
                        offset == 32 * 1024,
                    )
                    .map_err(|_| failed("prefill DATA"))?;
                submitted += count;
            }
            replies.push(reply);
            writers.push(writer);
        }
        // PING may overtake queued DATA. First observe complete DATA frames in
        // successful client IO writes, then enqueue a fresh PING behind them.
        let data_written = timeout_at(active_end, data_evidence.complete())
            .await
            .map_err(|_| failed("original DATA wire completion deadline"))??;
        timeout_at(active_end, ping.ping(wire::Ping::opaque()))
            .await
            .map_err(|_| failed("post-DATA PING deadline"))?
            .map_err(|_| failed("post-DATA PING barrier"))?;
        let updates = wire_evidence.lock().unwrap().updates()?;
        sender = sender
            .ready()
            .await
            .map_err(|_| failed("third original request ready"))?;
        let (reply, mut writer) = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://a.test/connection-credit/2")
                    .header("content-length", 65_536)
                    .body(())
                    .unwrap(),
                false,
            )
            .map_err(|_| failed("third original request headers"))?;
        held.wait_for(3).await;
        writer.reserve_capacity(8192);
        let before = writer.capacity();
        let timed_out = {
            let wait = timeout_at(active_end, poll_fn(|cx| writer.poll_capacity(cx)));
            tokio::pin!(wait);
            let pending = poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx).is_pending())).await;
            if !pending {
                return Err(failed("exhausted connection unexpectedly granted DATA"));
            }
            tokio::time::advance(active_end.saturating_duration_since(Instant::now())).await;
            // Drive the real timer wheel tick without changing the 60s deadline.
            tokio::time::advance(Duration::from_millis(2)).await;
            wait.await.is_err()
        };
        let after = writer.capacity();
        replies.push(reply);
        writers.push(writer);
        let held_before_cancel = held.live.load(Ordering::Acquire);
        let core_running = !owner.is_finished();
        let client_running = driver.as_ref().is_some_and(|owner| !owner.is_finished());
        let data_after_wait = data_evidence.frames.lock().unwrap().snapshot()?;
        Ok::<_, io::Error>((
            submitted,
            before,
            after,
            timed_out,
            Instant::now(),
            held.entered.load(Ordering::Acquire),
            second_grants,
            second_grant_count,
            updates,
            data_written,
            data_after_wait,
            held_before_cancel,
            core_running,
            client_running,
        ))
    })
    .await;
    stop.cancel();
    let core = joined(owner).await;
    held.release.cancel();
    let client = match driver {
        Some(driver) => Some(joined(driver).await),
        None => None,
    };
    origin.join().await;
    // No assertions before original request/driver/Core ownership is released.
    assert!(core.as_ref().is_ok_and(|result| result.is_ok()), "{core:?}");
    assert!(
        client.as_ref().is_some_and(|join| join.is_ok()),
        "client owner did not join: {client:?}"
    );
    // Keep the protocol result distinct: controlled Core cancellation may
    // produce an H2/IO error even though the actual owner joined successfully.
    let _client_protocol_result = client.unwrap().unwrap();
    assert_eq!(live.load(Ordering::Acquire), 0);
    assert_eq!(held.live.load(Ordering::Acquire), 0);
    assert_eq!(held.physical_calls.load(Ordering::Acquire), 0);
    let (
        submitted,
        before,
        after,
        timed_out,
        finished,
        entered,
        second_grants,
        second_grant_count,
        updates,
        data_written,
        data_after_wait,
        held_before_cancel,
        core_running,
        client_running,
    ) = observed.unwrap().unwrap();
    assert_eq!(
        data_written,
        DataSnapshot {
            bytes: [32 * 1024; 2],
            end_streams: 3
        }
    );
    assert_eq!(
        data_after_wait, data_written,
        "no third-stream DATA or replay"
    );
    assert_eq!(
        held_before_cancel, 3,
        "original Sources remained held at the deadline"
    );
    assert!(
        core_running && client_running,
        "owners must not retire before the original capacity timeout"
    );
    assert_eq!(submitted, 65_536);
    assert_eq!(second_grant_count, 2);
    assert_eq!(
        second_grants,
        [32_767, 1],
        "the last byte still required real connection feedback"
    );
    assert_eq!(updates, (1, 1));
    assert_eq!(65_535 + updates.1, 65_536);
    assert_eq!((before, after), (0, 0));
    assert!(timed_out && finished >= active_end && finished < start + Duration::from_secs(61));
    assert_eq!(entered, 3, "no request was replayed or invented");
}

#[cfg(all(unix, feature = "inbound-http"))]
#[forbid(unsafe_code)]
mod shared_collector_recvstream_tests {
    include!("shared_collector_h2_recvstream_memory_test.rs");
}
