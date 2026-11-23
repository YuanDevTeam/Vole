//! Fixed duplex-H2 ownership probes. These do not authenticate TLS.
use super::*;
use crate::http_processing::body_budget::{Budget, BudgetedBytes, WORKSPACE};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{sync::Mutex as StdMutex, task::Context};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::time::timeout;

const PAYLOAD: &[u8] = b"owned-h2-body";
struct CountedIo {
    io: DuplexStream,
    live: Arc<AtomicUsize>,
}
impl CountedIo {
    fn new(io: DuplexStream, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::AcqRel);
        Self {
            io,
            live: live.clone(),
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
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn identity() -> Identity {
    Identity::new(
        HttpTcpReuseKey::new(7_u8),
        &"https://memory.invalid/".parse().unwrap(),
    )
}
fn io_error<E>(_error: E) -> io::Error {
    failed()
}

struct Fixture {
    client: StdMutex<Option<BoxStream>>,
    peer: Option<CountedIo>,
    live_io: Arc<AtomicUsize>,
    opens: AtomicUsize,
    budget: Budget,
    last_slice: Arc<StdMutex<Option<Bytes>>>,
    ping: CancellationToken,
    pong: CancellationToken,
}
impl Fixture {
    fn new() -> Self {
        let (client, peer) = tokio::io::duplex(8192);
        let live_io = Arc::new(AtomicUsize::new(0));
        Self {
            client: StdMutex::new(Some(Box::new(CountedIo::new(client, &live_io)))),
            peer: Some(CountedIo::new(peer, &live_io)),
            live_io,
            opens: AtomicUsize::new(0),
            budget: Budget::default(),
            last_slice: Arc::new(StdMutex::new(None)),
            ping: CancellationToken::new(),
            pong: CancellationToken::new(),
        }
    }
    // Only this cfg(test/explicit Apple suite) factory bypasses TLS. Production
    // acquire's factory is StandardTlsClient::connect_negotiated, not this one.
    async fn open(&self) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        self.opens.fetch_add(1, Ordering::AcqRel);
        let io = self
            .client
            .lock()
            .map_err(io_error)?
            .take()
            .ok_or_else(failed)?;
        Ok((io, Some(b"h2".to_vec())))
    }
    fn peer(
        &mut self,
        expected: usize,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'static {
        let io = self.peer.take().unwrap();
        let budget = self.budget.clone();
        let last_slice = self.last_slice.clone();
        let ping = self.ping.clone();
        let pong = self.pong.clone();
        async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(32 * 1024)
                .initial_connection_window_size(64 * 1024)
                .handshake::<_, Bytes>(io)
                .await
                .map_err(io_error)?;
            let mut pings = connection.ping_pong().ok_or_else(failed)?;
            let mut sent_ping = false;
            let mut got_pong = false;
            let mut accepted = 0;
            loop {
                tokio::select! {biased;
                    ()=ping.cancelled(),if !sent_ping=>{
                        pings.send_ping(h2::Ping::opaque()).map_err(io_error)?;
                        sent_ping=true;
                    },
                    result=poll_fn(|cx|pings.poll_pong(cx)),if sent_ping && !got_pong=>{
                        result.map_err(io_error)?; got_pong=true; pong.cancel();
                    },
                    incoming=connection.accept()=>match incoming {
                        Some(Ok((request,mut response)))=>{
                            if request.method()!=http::Method::GET || !request.body().is_end_stream() || accepted>=expected {
                                return Err(failed());
                            }
                            accepted+=1;
                            let mut output=BudgetedBytes::new(&budget,PAYLOAD.len()).ok_or(io::ErrorKind::OutOfMemory)?;
                            output.extend(PAYLOAD)?;
                            let bytes=output.into_bytes();
                            *last_slice.lock().map_err(io_error)?=Some(bytes.slice(..));
                            let mut body=response.send_response(Response::builder().header("content-length",PAYLOAD.len()).body(()).map_err(io_error)?,false).map_err(io_error)?;
                            body.send_data(bytes,true).map_err(io_error)?;
                        },
                        Some(Err(_))|None=>return if accepted==expected {Ok(accepted)} else {Err(failed())},
                    }
                }
            }
        }
    }
}

async fn read_response(mut sender: h2::client::SendRequest<Bytes>) -> io::Result<()> {
    let (response, _) = sender
        .send_request(
            Request::builder()
                .uri("https://memory.invalid/probe")
                .body(())
                .map_err(io_error)?,
            true,
        )
        .map_err(io_error)?;
    let response = response.await.map_err(io_error)?;
    if response.status() != http::StatusCode::OK {
        return Err(failed());
    }
    let mut body = response.into_body();
    let mut offset = 0;
    while let Some(bytes) = body.data().await {
        let bytes = bytes.map_err(io_error)?;
        if offset + bytes.len() > PAYLOAD.len()
            || bytes.as_ref() != &PAYLOAD[offset..offset + bytes.len()]
        {
            return Err(failed());
        }
        offset += bytes.len();
        body.flow_control()
            .release_capacity(bytes.len())
            .map_err(io_error)?;
    }
    if offset != PAYLOAD.len() {
        return Err(failed());
    }
    Ok(())
}

async fn shared_idle_retire() -> io::Result<Value> {
    let mut fixture = Fixture::new();
    let mut peer = Box::pin(fixture.peer(2));
    let (sessions, mut parent) = new();
    let operation = async {
        let Acquired::Shared {
            lease: first,
            sender,
        } = sessions
            .acquire(identity(), Instant::now() + SETUP, || fixture.open())
            .await?
        else {
            return Err(failed());
        };
        read_response(sender).await?;
        let state = first.state.clone();
        drop(first);
        let idle =
            state.leases.load(Ordering::Acquire) == 0 && !state.closed.load(Ordering::Acquire);
        fixture.ping.cancel();
        fixture.pong.cancelled().await;
        let Acquired::Shared {
            lease: second,
            sender,
        } = sessions
            .acquire(identity(), Instant::now() + SETUP, || fixture.open())
            .await?
        else {
            return Err(failed());
        };
        let same = Arc::ptr_eq(&state, &second.state);
        read_response(sender).await?;
        drop(sessions.slot.lock().await.take());
        let retained = state.retired.load(Ordering::Acquire)
            && !state.closed.load(Ordering::Acquire)
            && state.leases.load(Ordering::Acquire) == 1
            && fixture.live_io.load(Ordering::Acquire) == 2;
        drop(second);
        while !state.closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        Ok::<_, io::Error>((idle, same, retained))
    };
    let mut operation = Box::pin(operation);
    // Without parent registration polling no sender may escape acquire.
    let waiting_for_ack = poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx).is_pending())).await
        && parent.registrations.len() == 1;
    let result = loop {
        tokio::select! {biased;
            ()=parent.progress()=>{},
            result=&mut operation=>break result?,
            result=&mut peer=>{let _=result?;return Err(failed());},
        }
    };
    drop(operation);
    drop(parent);
    let accepted = peer.await?;
    drop(sessions);
    let io_released = fixture.live_io.load(Ordering::Acquire) == 0;
    let final_slice_paid = fixture.budget.reserve(WORKSPACE).is_none();
    drop(fixture.last_slice.lock().map_err(io_error)?.take());
    let refunded = fixture.budget.reserve(WORKSPACE).is_some();
    let opens = fixture.opens.load(Ordering::Acquire);
    Ok(
        json!({"id":"h2-parent-register-idle-retire","passed":waiting_for_ack && result.0 && result.1 && result.2 && accepted==2 && opens==1 && io_released && final_slice_paid && refunded,
        "registrationAckRequired":waiting_for_ack,"sameSession":result.1,"idlePingPong":fixture.pong.is_cancelled(),"leaseRetainedAfterEviction":result.2,
        "connectionsOpened":opens,"acceptedRequests":accepted,"ioOwnersReleased":io_released,"lastBodySliceStillPaid":final_slice_paid,"lastBodyOwnerRefunded":refunded}),
    )
}

async fn cancel_active() -> io::Result<Value> {
    let mut fixture = Fixture::new();
    let mut peer = Box::pin(fixture.peer(1));
    let (sessions, mut parent) = new();
    let headers = CancellationToken::new();
    let state = StdMutex::new(None::<Arc<State>>);
    let operation = async {
        let Acquired::Shared { lease, mut sender } = sessions
            .acquire(identity(), Instant::now() + SETUP, || fixture.open())
            .await?
        else {
            return Err(failed());
        };
        *state.lock().map_err(io_error)? = Some(lease.state.clone());
        let (response, _) = sender
            .send_request(
                Request::builder()
                    .uri("https://memory.invalid/cancel")
                    .body(())
                    .map_err(io_error)?,
                true,
            )
            .map_err(io_error)?;
        let incoming = response.await.map_err(io_error)?;
        let _body = incoming.into_body();
        headers.cancel();
        // This is the actual pending request future/lease, not a drop counter
        // standing in for one. Parent cancellation drops it before the driver.
        std::future::pending::<()>().await;
        drop(lease);
        Ok::<_, io::Error>(())
    };
    let mut operation = Box::pin(operation);
    loop {
        tokio::select! {biased;
            ()=parent.progress()=>{},
            ()=headers.cancelled()=>break,
            result=&mut operation=>{result?;return Err(failed());},
            result=&mut peer=>{let _=result?;return Err(failed());},
        }
    }
    let active = state
        .lock()
        .map_err(io_error)?
        .as_ref()
        .is_some_and(|s| s.leases.load(Ordering::Acquire) == 1);
    drop(operation);
    drop(parent);
    let accepted = peer.await?;
    drop(sessions);
    let lease_released =
        state.lock().map_err(io_error)?.as_ref().is_some_and(|s| {
            s.leases.load(Ordering::Acquire) == 0 && s.closed.load(Ordering::Acquire)
        });
    let io_released = fixture.live_io.load(Ordering::Acquire) == 0;
    let final_slice_paid = fixture.budget.reserve(WORKSPACE).is_none();
    drop(fixture.last_slice.lock().map_err(io_error)?.take());
    let refunded = fixture.budget.reserve(WORKSPACE).is_some();
    Ok(
        json!({"id":"h2-parent-active-cancel","passed":active && lease_released && accepted==1 && io_released && final_slice_paid && refunded,
        "realRequestPending":active,"leaseReleased":lease_released,"ioOwnersReleased":io_released,"lastBodySliceStillPaid":final_slice_paid,"lastBodyOwnerRefunded":refunded}),
    )
}

async fn probes() -> io::Result<Value> {
    let rows = vec![
        shared_idle_retire().await?,
        cancel_active().await?,
        cancel_before_ack().await?,
        unsupported_alpn().await?,
        downstream_send_capacity().await?,
        super::super::h2_body::request_upload_validation::probe().await?,
    ];
    let passed = rows.iter().all(|row| row["passed"] == true);
    Ok(
        json!({"id":"h2-upstream-owner-lifecycle","kind":"h2-memory-owner-group","passed":passed,"probeCount":rows.len(),"probes":rows,
        "scope":"private fixed duplex H2 only; shared production register/ack, driver and lease code; no TLS authentication or network acceptance",
        "tlsAuthenticationExercised":false,"externalIO":false,"backgroundTasksSpawned":false,"joined":true}),
    )
}
async fn cancel_before_ack() -> io::Result<Value> {
    let mut fixture = Fixture::new();
    let (sessions, parent) = new();
    let mut body =
        BudgetedBytes::new(&fixture.budget, PAYLOAD.len()).ok_or(io::ErrorKind::OutOfMemory)?;
    body.extend(PAYLOAD)?;
    let body = body.into_bytes();
    let last_slice = body.slice(..);
    let operation = async {
        let _body_owner = body;
        let _result = sessions
            .acquire(identity(), Instant::now() + SETUP, || fixture.open())
            .await?;
        std::future::pending::<()>().await;
        Ok::<_, io::Error>(())
    };
    let mut operation = Box::pin(operation);
    let queued = poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx).is_pending())).await
        && parent.registrations.len() == 1;
    let body_paid = fixture.budget.reserve(WORKSPACE).is_none();
    drop(operation);
    // The not-yet-polled registered driver is still a real I/O owner in the
    // parent's channel. Dropping its parent closes it without publication.
    drop(parent);
    drop(sessions);
    drop(fixture.peer.take());
    let io_released = fixture.live_io.load(Ordering::Acquire) == 0;
    let last_slice_paid = fixture.budget.reserve(WORKSPACE).is_none();
    drop(last_slice);
    let refunded = fixture.budget.reserve(WORKSPACE).is_some();
    Ok(
        json!({"id":"h2-parent-cancel-before-register-ack","passed":queued && body_paid && io_released && last_slice_paid && refunded,
        "registrationQueuedWithoutPublication":queued,"realBodyOwnerPaid":body_paid,"ioOwnersReleased":io_released,"lastBodySliceStillPaid":last_slice_paid,"lastBodyOwnerRefunded":refunded}),
    )
}
async fn unsupported_alpn() -> io::Result<Value> {
    let mut fixture = Fixture::new();
    let (sessions, parent) = new();
    let result = sessions
        .acquire(identity(), Instant::now() + SETUP, || async {
            let (io, _) = fixture.open().await?;
            Ok((io, Some(b"not-http".to_vec())))
        })
        .await;
    let rejected =
        matches!(result,Err(ref error) if error.kind()==io::ErrorKind::ConnectionAborted);
    let never_registered = parent.registrations.is_empty() && parent.drivers.is_empty();
    drop(result);
    drop(parent);
    drop(sessions);
    drop(fixture.peer.take());
    let released = fixture.live_io.load(Ordering::Acquire) == 0;
    Ok(
        json!({"id":"h2-unexpected-alpn-rejected","passed":rejected && never_registered && released,"rejected":rejected,"neverRegistered":never_registered,"ioOwnersReleased":released}),
    )
}
#[cfg(all(target_vendor = "apple", feature = "http-diagnostics"))]
pub(super) fn run() -> io::Result<Value> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let result = runtime.block_on(async { timeout(Duration::from_secs(5), probes()).await });
    drop(runtime);
    let mut result = result.map_err(|_| io::ErrorKind::TimedOut)??;
    result["runtimeDropped"] = json!(true);
    Ok(result)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn h2_reuse_parent_register_idle_ping_retire_and_cancel_keep_real_owners() {
        let result = super::timeout(super::Duration::from_secs(5), super::probes())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["passed"], true, "{result}");
    }
}

// Control fixtures below use real H2 framing/credit and the unchanged business
// send helper. They never invoke TLS or introduce a production input factory.
const SEND_PROBE_BYTES: usize = 64 * 1024;
const PEER_CREDIT: u32 = 128 * 1024;
struct MeteredIo {
    io: CountedIo,
    activity: Arc<AtomicUsize>,
}
impl AsyncRead for MeteredIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if buf.filled().len() != before {
            self.activity.fetch_add(1, Ordering::AcqRel);
        }
        result
    }
}
impl AsyncWrite for MeteredIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, data);
        if matches!(result,Poll::Ready(Ok(n)) if n>0) {
            self.activity.fetch_add(1, Ordering::AcqRel);
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
type ProbeClient = h2::client::Connection<MeteredIo, Bytes>;
type ProbeServer = h2::server::Connection<MeteredIo, Bytes>;
struct SendReceiver {
    response: h2::client::ResponseFuture,
    body: Option<h2::RecvStream>,
    received: usize,
    frames: usize,
    max_frame: usize,
    held_credit: usize,
    complete: bool,
}
impl SendReceiver {
    fn release_credit(&mut self) -> io::Result<()> {
        if self.held_credit != 0 {
            self.body
                .as_mut()
                .ok_or_else(failed)?
                .flow_control()
                .release_capacity(std::mem::take(&mut self.held_credit))
                .map_err(io_error)?;
        }
        Ok(())
    }
    fn poll_available(&mut self, cx: &mut Context<'_>, release: bool) -> io::Result<()> {
        if self.body.is_none() {
            match Pin::new(&mut self.response).poll(cx) {
                Poll::Ready(Ok(response)) => {
                    if response.status() != http::StatusCode::OK {
                        return Err(failed());
                    }
                    self.body = Some(response.into_body());
                }
                Poll::Ready(Err(_)) => return Err(failed()),
                Poll::Pending => return Ok(()),
            }
        }
        let body = self.body.as_mut().ok_or_else(failed)?;
        if release && self.held_credit != 0 {
            body.flow_control()
                .release_capacity(std::mem::take(&mut self.held_credit))
                .map_err(io_error)?;
        }
        if self.complete {
            return Ok(());
        }
        loop {
            match body.poll_data(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if self.received + bytes.len() > SEND_PROBE_BYTES
                        || !bytes
                            .iter()
                            .enumerate()
                            .all(|(i, b)| *b == ((self.received + i) % 256) as u8)
                    {
                        return Err(failed());
                    }
                    self.received += bytes.len();
                    self.frames += 1;
                    self.max_frame = self.max_frame.max(bytes.len());
                    if release {
                        body.flow_control()
                            .release_capacity(bytes.len())
                            .map_err(io_error)?;
                    } else {
                        self.held_credit += bytes.len();
                    }
                }
                Poll::Ready(Some(Err(_))) => return Err(failed()),
                Poll::Ready(None) => {
                    self.complete = true;
                    return Ok(());
                }
                Poll::Pending => return Ok(()),
            }
        }
    }
}
fn poll_send_connections(
    client: &mut ProbeClient,
    server: &mut ProbeServer,
    cx: &mut Context<'_>,
) -> io::Result<()> {
    if Pin::new(client).poll(cx).is_ready() || server.poll_accept(cx).is_ready() {
        return Err(failed());
    }
    Ok(())
}
async fn settle_send_connections(
    client: &mut ProbeClient,
    server: &mut ProbeServer,
    receiver: &mut SendReceiver,
    activity: &AtomicUsize,
) -> io::Result<()> {
    // Finite in-memory quiescence passes; an explicit yield replenishes the
    // runtime's cooperative budget rather than interpreting its yield as EOF.
    for _ in 0..4 {
        poll_fn(|cx| {
            for _ in 0..32 {
                let before = activity.load(Ordering::Acquire);
                poll_send_connections(client, server, cx)?;
                receiver.poll_available(cx, false)?;
                if activity.load(Ordering::Acquire) == before {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Ready(Err(failed()))
        })
        .await?;
        tokio::task::yield_now().await;
    }
    Ok(())
}
async fn send_capacity_case(limit: usize, initial_window: u32) -> io::Result<Value> {
    let budget = Budget::default();
    let live = Arc::new(AtomicUsize::new(0));
    let activity = Arc::new(AtomicUsize::new(0));
    let (client_io, server_io) = tokio::io::duplex(8192);
    let client_io = MeteredIo {
        io: CountedIo::new(client_io, &live),
        activity: activity.clone(),
    };
    let server_io = MeteredIo {
        io: CountedIo::new(server_io, &live),
        activity: activity.clone(),
    };
    let mut client_builder = h2::client::Builder::new();
    client_builder
        .initial_window_size(initial_window)
        .initial_connection_window_size(PEER_CREDIT)
        .header_table_size(0)
        .max_frame_size(16 * 1024);
    let (sender, mut client) = client_builder
        .handshake::<_, Bytes>(client_io)
        .await
        .map_err(io_error)?;
    let mut server_builder = h2::server::Builder::new();
    server_builder
        .initial_window_size(32 * 1024)
        .initial_connection_window_size(64 * 1024)
        .header_table_size(0)
        .max_frame_size(16 * 1024)
        .max_send_buffer_size(limit);
    let mut handshake = Box::pin(server_builder.handshake::<_, Bytes>(server_io));
    let mut server = tokio::select! {biased;
        result=&mut handshake=>result.map_err(io_error)?,
        _=&mut client=>return Err(failed()),
    };
    drop(handshake);
    let mut sender = sender.ready().await.map_err(io_error)?;
    let (response, _) = sender
        .send_request(
            Request::builder()
                .uri("https://memory.invalid/send-credit")
                .body(())
                .map_err(io_error)?,
            true,
        )
        .map_err(io_error)?;
    let (request, mut response_sender) = tokio::select! {biased;
        accepted=server.accept()=>accepted.ok_or_else(failed)?.map_err(io_error)?,
        _=&mut client=>return Err(failed()),
    };
    if !request.body().is_end_stream() {
        return Err(failed());
    }
    drop(request);
    let mut target = response_sender
        .send_response(
            Response::builder()
                .header("content-length", SEND_PROBE_BYTES)
                .body(())
                .map_err(io_error)?,
            false,
        )
        .map_err(io_error)?;
    let mut receiver = SendReceiver {
        response,
        body: None,
        received: 0,
        frames: 0,
        max_frame: 0,
        held_credit: 0,
        complete: false,
    };
    // Drain the actual initial SETTINGS / connection WINDOW_UPDATE before
    // pausing this server driver. No DATA has been queued at this point.
    settle_send_connections(&mut client, &mut server, &mut receiver, &activity).await?;
    let mut pings = client.ping_pong().ok_or_else(failed)?;
    pings.send_ping(h2::Ping::opaque()).map_err(io_error)?;
    poll_fn(|cx| {
        poll_send_connections(&mut client, &mut server, cx)?;
        pings
            .poll_pong(cx)
            .map(|result| result.map(|_| ()).map_err(io_error))
    })
    .await?;
    settle_send_connections(&mut client, &mut server, &mut receiver, &activity).await?;
    if receiver.body.is_none() || receiver.received != 0 {
        return Err(failed());
    }
    let mut output =
        BudgetedBytes::new(&budget, SEND_PROBE_BYTES).ok_or(io::ErrorKind::OutOfMemory)?;
    let block: [u8; 256] = std::array::from_fn(|i| i as u8);
    for _ in 0..SEND_PROBE_BYTES / 256 {
        output.extend(&block)?;
    }
    let output = output.into_bytes();
    let last_slice = output.slice(..);
    let mut producer = Box::pin(crate::http_processing::h2_body::send_data(
        &mut target,
        output,
    ));
    // No server/client poll in this call: only production reserve/poll/send.
    let initially_ready = poll_fn(|cx| {
        Poll::Ready(match producer.as_mut().poll(cx) {
            Poll::Ready(result) => result.map(|_| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    // Resume both real drivers, but keep the producer itself paused; received
    // bytes are exactly the prefix that was queued during that one manual poll.
    settle_send_connections(&mut client, &mut server, &mut receiver, &activity).await?;
    let prefix = receiver.received;
    let prefix_frames = receiver.frames;
    let expected_prefix = (initial_window as usize).min(limit).min(SEND_PROBE_BYTES);
    let ready_expected = expected_prefix == SEND_PROBE_BYTES;
    let prefix_correct =
        prefix == expected_prefix && prefix_frames == expected_prefix.div_ceil(16 * 1024);
    // Grow low/zero credit via the real public SETTINGS path, then drain the
    // same producer future and original body; there is no replay/reconstruction.
    if initial_window < PEER_CREDIT {
        client
            .set_initial_window_size(PEER_CREDIT)
            .map_err(io_error)?;
    }
    receiver.release_credit()?;
    if !initially_ready {
        poll_fn(|cx| {
            poll_send_connections(&mut client, &mut server, cx)?;
            receiver.poll_available(cx, true)?;
            producer.as_mut().poll(cx)
        })
        .await?;
    }
    drop(producer);
    crate::http_processing::h2_body::finish(&mut target, None, false)?;
    poll_fn(|cx| {
        poll_send_connections(&mut client, &mut server, cx)?;
        receiver.poll_available(cx, true)?;
        if receiver.complete {
            Poll::Ready(Ok::<_, io::Error>(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let received = receiver.received;
    let max_frame = receiver.max_frame;
    let full = received == SEND_PROBE_BYTES && receiver.complete && max_frame <= 16 * 1024;
    drop(receiver);
    drop(target);
    drop(response_sender);
    drop(sender);
    drop(pings);
    drop(server);
    drop(client);
    let io_released = live.load(Ordering::Acquire) == 0;
    let last_paid = budget.reserve(WORKSPACE).is_none();
    drop(last_slice);
    let refunded = budget.reserve(WORKSPACE).is_some();
    Ok(
        json!({"sendQueueBytes":limit,"initialPeerStreamWindowBytes":initial_window,"peerConnectionWindowBytes":PEER_CREDIT,
        "pausedProducerReady":initially_ready,"pausedPrefixBytes":prefix,"pausedPrefixFrames":prefix_frames,"expectedPrefixBytes":expected_prefix,
        "controlPingPong":true,"fullBodyBytesVerified":received,"maxDataFrameBytes":max_frame,"maxDataFrameAtMost16KiB":max_frame<=16*1024,
        "ioOwnersReleased":io_released,"lastBodySliceStillPaid":last_paid,"lastBodyOwnerRefunded":refunded,
        "passed":initially_ready==ready_expected && prefix_correct && full && io_released && last_paid && refunded}),
    )
}
async fn downstream_send_capacity() -> io::Result<Value> {
    let mut variants = Vec::new();
    for (limit, window) in [
        (16 * 1024, PEER_CREDIT),
        (64 * 1024, PEER_CREDIT),
        (64 * 1024, 0),
        (64 * 1024, 8 * 1024),
    ] {
        variants.push(send_capacity_case(limit, window).await?);
    }
    let passed = variants.iter().all(|row| row["passed"] == true);
    Ok(
        json!({"id":"h2-downstream-send-capacity","passed":passed,"variantCount":variants.len(),"variants":variants,
        "scope":"real duplex H2 control queues16/64 and production h2_body::send_data; no TLS; no production builder introspection",
        "backgroundTasksSpawned":false,"joined":true}),
    )
}
