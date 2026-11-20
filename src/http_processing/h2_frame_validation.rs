//! Synthetic duplex wire regressions for the official h2 dependency.
//! Exercises actual frames without host peers or production diagnostics.
#![cfg(feature = "inbound-http")]
use bytes::Bytes;
use futures_util::future::poll_fn;
use http::{HeaderMap, HeaderValue, Request, Response};
use sha2::{Digest, Sha256};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const LIMIT: Duration = Duration::from_secs(10);
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const PROOF: &str = "x-write-buffer-proof";
const TRAILER: &str = "x-write-buffer-trailer";

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

#[derive(Default)]
struct Trace {
    wire: Mutex<Vec<u8>>,
    owners: AtomicUsize,
    short_writes: AtomicUsize,
    pending_writes: AtomicUsize,
    pending_flushes: AtomicUsize,
    completed_flushes: AtomicUsize,
}

// One fixed non-vectored wrapper, with bounded synthetic wire recording.
struct ShortIo {
    io: Arc<Mutex<DuplexStream>>,
    trace: Arc<Trace>,
    write_pending: bool,
    flush_pending: bool,
}
impl ShortIo {
    fn new(io: Arc<Mutex<DuplexStream>>, trace: &Arc<Trace>) -> Self {
        trace.owners.fetch_add(1, Ordering::AcqRel);
        Self {
            io,
            trace: trace.clone(),
            write_pending: true,
            flush_pending: true,
        }
    }
}
impl Drop for ShortIo {
    fn drop(&mut self) {
        self.trace.owners.fetch_sub(1, Ordering::AcqRel);
    }
}
impl AsyncRead for ShortIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io.lock().map_err(|_| failure("IO lock poisoned"))?).poll_read(cx, buf)
    }
}
impl AsyncWrite for ShortIo {
    fn is_write_vectored(&self) -> bool {
        false
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_pending {
            self.write_pending = false;
            self.trace.pending_writes.fetch_add(1, Ordering::AcqRel);
            cx.waker().wake_by_ref();
            return Poll::Pending; // No bytes accepted on Pending.
        }
        let count = bytes.len().min(37);
        let result = {
            let mut io = self.io.lock().map_err(|_| failure("IO lock poisoned"))?;
            Pin::new(&mut *io).poll_write(cx, &bytes[..count])
        };
        match result {
            Poll::Ready(Ok(written)) => {
                {
                    let mut wire = self
                        .trace
                        .wire
                        .lock()
                        .map_err(|_| failure("wire lock poisoned"))?;
                    if wire.len() + written > 512 * 1024 {
                        return Poll::Ready(Err(failure("synthetic wire bound exceeded")));
                    }
                    wire.extend_from_slice(&bytes[..written]);
                }
                self.trace
                    .short_writes
                    .fetch_add(usize::from(written < bytes.len()), Ordering::AcqRel);
                self.write_pending = true;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush_pending {
            self.flush_pending = false;
            self.trace.pending_flushes.fetch_add(1, Ordering::AcqRel);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = {
            let mut io = self.io.lock().map_err(|_| failure("IO lock poisoned"))?;
            Pin::new(&mut *io).poll_flush(cx)
        };
        if matches!(result, Poll::Ready(Ok(()))) {
            self.trace.completed_flushes.fetch_add(1, Ordering::AcqRel);
            self.flush_pending = true;
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io.lock().map_err(|_| failure("IO lock poisoned"))?).poll_shutdown(cx)
    }
}

fn check_proof(headers: &HeaderMap, name: &str, proof: &HeaderValue) -> io::Result<()> {
    if headers.get(name).map(HeaderValue::as_bytes) != Some(proof.as_bytes()) {
        return Err(failure("complete header/trailer value mismatch"));
    }
    Ok(())
}
fn check_payload(actual: &[u8], expected: &[u8]) -> io::Result<()> {
    if actual != expected || Sha256::digest(actual).to_vec() != Sha256::digest(expected).to_vec() {
        return Err(failure("complete payload or SHA-256 mismatch"));
    }
    Ok(())
}
async fn receive(
    mut body: h2::RecvStream,
    expected: &Bytes,
    proof: &HeaderValue,
    trailers: bool,
) -> io::Result<()> {
    let mut actual = Vec::with_capacity(expected.len());
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        if actual.len() + chunk.len() > expected.len() {
            return Err(failure("body too long"));
        }
        actual.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(io::Error::other)?;
    }
    check_payload(&actual, expected)?;
    match (trailers, body.trailers().await.map_err(io::Error::other)?) {
        (true, Some(fields)) => check_proof(&fields, TRAILER, proof),
        (false, None) => Ok(()),
        _ => Err(failure("missing or unexpected trailers")),
    }
}
async fn send(
    body: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
    proof: &HeaderValue,
    trailers: bool,
) -> io::Result<()> {
    if bytes.is_empty() && !trailers {
        body.send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
    }
    while !bytes.is_empty() {
        body.reserve_capacity(bytes.len().min(16 * 1024));
        let available = poll_fn(|cx| body.poll_capacity(cx))
            .await
            .ok_or_else(|| failure("send stream closed"))?
            .map_err(io::Error::other)?;
        if available == 0 {
            continue;
        }
        let count = bytes.len().min(available).min(16 * 1024);
        let eos = count == bytes.len() && !trailers;
        body.send_data(bytes.split_to(count), eos)
            .map_err(io::Error::other)?;
    }
    if trailers {
        let mut fields = HeaderMap::new();
        fields.insert(TRAILER, proof.clone());
        body.send_trailers(fields).map_err(io::Error::other)?;
    }
    Ok(())
}

async fn serve(
    io: ShortIo,
    expected: Bytes,
    proof: HeaderValue,
    trailers: bool,
    cancel: CancellationToken,
) -> io::Result<()> {
    let builder = h2::server::Builder::new();
    let mut connection = tokio::select! { biased;
        () = cancel.cancelled() => return Err(failure("server cancelled")),
        result = builder.handshake::<_, Bytes>(io) => result.map_err(io::Error::other)?,
    };
    let (request, mut response) = tokio::select! { biased;
        () = cancel.cancelled() => return Err(failure("server cancelled")),
        result = connection.accept() => result.ok_or_else(|| failure("request absent"))?.map_err(io::Error::other)?,
    };
    {
        let exchange = async {
            check_proof(request.headers(), PROOF, &proof)?;
            receive(request.into_body(), &expected, &proof, trailers).await?;
            let reply = Response::builder()
                .status(200)
                .header(PROOF, proof.clone())
                .header("content-length", expected.len().to_string())
                .body(())
                .map_err(io::Error::other)?;
            let mut upload = response
                .send_response(reply, false)
                .map_err(io::Error::other)?;
            send(&mut upload, expected.clone(), &proof, trailers).await
        };
        tokio::pin!(exchange);
        tokio::select! { biased;
            () = cancel.cancelled() => return Err(failure("server cancelled")),
            result = &mut exchange => result?,
            _ = connection.accept() => return Err(failure("extra request or early connection close")),
        }
    }
    drop(response);
    connection.graceful_shutdown();
    tokio::select! { biased;
        () = cancel.cancelled() => Err(failure("server cancelled")),
        result = poll_fn(|cx| connection.poll_closed(cx)) => result.map_err(io::Error::other),
    }
}

async fn join_driver(
    task: Option<JoinHandle<io::Result<()>>>,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let Some(mut task) = task else {
        return Ok(());
    };
    match timeout(LIMIT, &mut task).await {
        Ok(result) => result.map_err(io::Error::other)?,
        Err(_) => {
            cancel.cancel();
            // Cancellation must be observed and the real future dropped before return.
            if timeout(LIMIT, &mut task).await.is_err() {
                task.abort();
                let _ = task.await; // Failing cleanup still joins; never detach.
            }
            Err(failure("driver join timed out"))
        }
    }
}

// Parse actual synthetic IO bytes, including all control frames between blocks.
fn check_wire(
    wire: &[u8],
    client: bool,
    expected: &[u8],
    large: bool,
    trailers: bool,
) -> io::Result<()> {
    let mut wire = if client {
        wire.strip_prefix(PREFACE)
            .ok_or_else(|| failure("missing client preface"))?
    } else {
        wire
    };
    let mut actual = Vec::new();
    let mut blocks = Vec::new(); // encoded bytes, frame count, first HEADERS flags
    let mut pending: Option<(usize, usize, u8)> = None;
    let mut data_eos = 0;
    while !wire.is_empty() {
        if wire.len() < 9 {
            return Err(failure("partial frame header after join"));
        }
        let size =
            (usize::from(wire[0]) << 16) | (usize::from(wire[1]) << 8) | usize::from(wire[2]);
        if size > 16 * 1024 || wire.len() < 9 + size {
            return Err(failure("invalid or partial frame after join"));
        }
        let (kind, flags) = (wire[3], wire[4]);
        let id = u32::from_be_bytes([wire[5], wire[6], wire[7], wire[8]]) & 0x7fff_ffff;
        let payload = &wire[9..9 + size];
        if pending.is_some() && (kind != 9 || id != 1) {
            return Err(failure("interleaved CONTINUATION"));
        }
        if id == 1 {
            match kind {
                1 | 9 => {
                    let mut block = if kind == 1 {
                        if flags & (8 | 32) != 0 {
                            return Err(failure("unexpected HEADERS padding/priority"));
                        }
                        (0, 0, flags)
                    } else {
                        pending
                            .take()
                            .ok_or_else(|| failure("orphan CONTINUATION"))?
                    };
                    block.0 += size;
                    block.1 += 1;
                    if flags & 4 != 0 {
                        blocks.push(block);
                    } else {
                        pending = Some(block);
                    }
                }
                0 => {
                    if flags & 8 != 0 {
                        return Err(failure("unexpected DATA padding"));
                    }
                    actual.extend_from_slice(payload);
                    if actual.len() > expected.len() {
                        return Err(failure("wire body too long"));
                    }
                    if flags & 1 != 0 {
                        data_eos += 1;
                        if actual.len() != expected.len() {
                            return Err(failure("early DATA EOS"));
                        }
                    }
                }
                _ => {}
            }
        }
        wire = &wire[9 + size..];
    }
    if pending.is_some() || blocks.len() != if trailers { 2 } else { 1 } {
        return Err(failure("incomplete or unexpected header blocks"));
    }
    for (index, (size, count, flags)) in blocks.iter().enumerate() {
        if (*size > 16 * 1024) != large
            || (!large && (*size <= 2048 || *count != 1))
            || (large && *count < 2)
        {
            return Err(failure("actual header block/CONTINUATION fixture mismatch"));
        }
        if (flags & 1 != 0) != (trailers && index == 1) {
            return Err(failure("HEADERS END_STREAM mismatch"));
        }
    }
    if data_eos != usize::from(!trailers) {
        return Err(failure("DATA END_STREAM count mismatch"));
    }
    check_payload(&actual, expected)
}

async fn case(body_len: usize, header_len: usize, trailers: bool) -> io::Result<()> {
    let expected = Bytes::from(
        (0..body_len)
            .map(|i| (i.wrapping_mul(131).wrapping_add(i / 251) & 255) as u8)
            .collect::<Vec<_>>(),
    );
    let text = (0..header_len)
        .map(|i| 33 + ((i * 73 + i / 29) % 94) as u8)
        .collect::<Vec<_>>();
    let mut proof = HeaderValue::from_bytes(&text).map_err(io::Error::other)?;
    proof.set_sensitive(true); // Preserve a genuinely large encoded block on fresh connections.
    let client_trace = Arc::new(Trace::default());
    let server_trace = Arc::new(Trace::default());
    let (client_io, server_io) = tokio::io::duplex(1024);
    let client_io = Arc::new(Mutex::new(client_io));
    let server_io = Arc::new(Mutex::new(server_io));
    let client_weak = Arc::downgrade(&client_io);
    let server_weak = Arc::downgrade(&server_io);
    let cancel = CancellationToken::new();
    let server = Some(tokio::spawn(serve(
        ShortIo::new(server_io.clone(), &server_trace),
        expected.clone(),
        proof.clone(),
        trailers,
        cancel.clone(),
    )));
    let mut client = None;
    let mut keepalive = None;
    let transfer = timeout(LIMIT, async {
        let builder = h2::client::Builder::new();
        let (sender, driver) = builder
            .handshake::<_, Bytes>(ShortIo::new(client_io.clone(), &client_trace))
            .await
            .map_err(io::Error::other)?;
        let stop = cancel.clone();
        client = Some(tokio::spawn(async move {
            tokio::select! { biased;
                () = stop.cancelled() => Err(failure("client cancelled")),
                result = driver => result.map_err(io::Error::other),
            }
        }));
        let mut sender = sender.ready().await.map_err(io::Error::other)?;
        let request = Request::builder()
            .method("POST")
            .uri("https://write-capacity.invalid/probe")
            .header(PROOF, proof.clone())
            .header("content-length", expected.len().to_string())
            .body(())
            .map_err(io::Error::other)?;
        let (response, mut upload) = sender
            .send_request(request, false)
            .map_err(io::Error::other)?;
        send(&mut upload, expected.clone(), &proof, trailers).await?;
        drop(upload);
        let response = response.await.map_err(io::Error::other)?;
        if response.status() != 200 {
            return Err(failure("response status mismatch"));
        }
        check_proof(response.headers(), PROOF, &proof)?;
        receive(response.into_body(), &expected, &proof, trailers).await?;
        keepalive = Some(sender);
        Ok(())
    })
    .await
    .unwrap_or_else(|_| Err(failure("wire exchange timed out")));
    if transfer.is_err() {
        cancel.cancel();
    }
    let server_done = join_driver(server, &cancel).await;
    if server_done.is_err() {
        cancel.cancel();
    }
    drop(keepalive);
    let client_done = join_driver(client, &cancel).await;
    cancel.cancel();
    drop(client_io);
    drop(server_io);
    if client_weak.upgrade().is_some() || server_weak.upgrade().is_some() {
        return Err(failure("transport owner survived joined drivers"));
    }
    // Check every terminal owner after both actual task joins, including error paths.
    if client_trace.owners.load(Ordering::Acquire) != 0
        || server_trace.owners.load(Ordering::Acquire) != 0
    {
        return Err(failure("IO owner survived joined drivers"));
    }
    if transfer.is_err() || server_done.is_err() || client_done.is_err() {
        return Err(io::Error::other(format!(
            "transfer={transfer:?};server={server_done:?};client={client_done:?}"
        )));
    }
    for (trace, is_client) in [(&client_trace, true), (&server_trace, false)] {
        if trace.short_writes.load(Ordering::Acquire) == 0
            || trace.pending_writes.load(Ordering::Acquire) == 0
            || trace.pending_flushes.load(Ordering::Acquire) == 0
            || trace.completed_flushes.load(Ordering::Acquire) == 0
        {
            return Err(failure("short/Pending/write/flush path was not exercised"));
        }
        let wire = trace
            .wire
            .lock()
            .map_err(|_| failure("wire lock poisoned"))?;
        check_wire(
            &wire,
            is_client,
            &expected,
            header_len > 16 * 1024,
            trailers,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn short_pending_headers_and_data_end_stream() {
    for length in [0, 64 * 1024] {
        let result = case(length, 6000, false).await;
        assert!(result.is_ok(), "joined wire case failed: {result:?}");
    }
}

#[tokio::test]
async fn continuation_headers_64k_data_and_trailers() {
    let result = case(64 * 1024, 30_000, true).await;
    assert!(result.is_ok(), "joined wire case failed: {result:?}");
}
