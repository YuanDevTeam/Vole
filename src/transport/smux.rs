//! Independent smux v1 client framing. One owned reader/writer pair, bounded
//! physical write queue and connection-budgeted receive queues; no detached workers.
use crate::dispatch::BoxStream;
use bytes::Buf;
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;
use tokio_util::sync::PollSender;

#[derive(Clone, Copy)]
pub(crate) struct Options {
    pub version: u8,
    pub frame_size: usize,
    pub receive_buffer: usize,
    pub stream_buffer: usize,
    pub keepalive: Option<std::time::Duration>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            version: 1,
            frame_size: crate::limits::SING_MUX_CHUNK,
            receive_buffer: 3 * 1024 * 1024,
            stream_buffer: crate::limits::SMUX_RECEIVE_QUEUE * crate::limits::SING_MUX_CHUNK,
            keepalive: None,
        }
    }
}
struct Packet {
    data: Bytes,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
// Charge each queued frame for its payload and a conservative bookkeeping fee.
// This is a connection admission budget, not a process RSS bound. A legal
// quota-sized frame must still make progress when the configured quota is small.
fn receive_charge(length: usize, budget: usize) -> usize {
    (length + 128).min(budget)
}
struct Flow {
    written: AtomicU32,
    consumed: AtomicU32,
    peer_consumed: AtomicU32,
    peer_window: AtomicU32,
    update: AtomicBool,
    changed: AtomicWaker,
}
impl Flow {
    fn new() -> Self {
        Self {
            written: AtomicU32::new(0),
            consumed: AtomicU32::new(0),
            peer_consumed: AtomicU32::new(0),
            peer_window: AtomicU32::new(262144),
            update: AtomicBool::new(false),
            changed: AtomicWaker::new(),
        }
    }
    fn credit(&self) -> u32 {
        self.peer_window.load(Ordering::Acquire).saturating_sub(
            self.written
                .load(Ordering::Acquire)
                .wrapping_sub(self.peer_consumed.load(Ordering::Acquire)),
        )
    }
}
enum Command {
    Frame(Frame),
    Flush(oneshot::Sender<io::Result<()>>),
}
struct Frame {
    cmd: u8,
    id: u32,
    data: Bytes,
    done: oneshot::Sender<io::Result<()>>,
}
struct Entry {
    receive: mpsc::Sender<Packet>,
    flow: Arc<Flow>,
    close: CancellationToken,
    remote_fin: Arc<AtomicBool>,
}
struct State {
    closed: bool,
    next: u32,
    streams: HashMap<u32, Entry>,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
    options: Options,
    autonomous_writes: bool,
}
#[derive(Clone)]
pub(crate) struct Client {
    shared: Arc<Shared>,
    write: mpsc::Sender<Command>,
}
impl Client {
    pub(crate) async fn open(&self) -> io::Result<BoxStream> {
        let permit = self
            .write
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| io::ErrorKind::ConnectionAborted)?;
        let budget = self.shared.options.receive_buffer;
        // Allocation permits bound live frames, so no individual stream queue
        // fills before the connection-wide byte budget is exhausted.
        let capacity = budget / receive_charge(1, budget);
        let (tx, receive) = mpsc::channel(capacity);
        let flow = Arc::new(Flow::new());
        let close = CancellationToken::new();
        let remote_fin = Arc::new(AtomicBool::new(false));
        let (id, done) = {
            let mut state = self.shared.state.lock().unwrap();
            if state.closed {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            state.next = state
                .next
                .checked_add(2)
                .ok_or(io::ErrorKind::ConnectionAborted)?;
            let id = state.next;
            state.streams.insert(
                id,
                Entry {
                    receive: tx,
                    flow: flow.clone(),
                    close: close.clone(),
                    remote_fin: remote_fin.clone(),
                },
            );
            let (tx, rx) = oneshot::channel();
            permit.send(Command::Frame(Frame {
                cmd: 0,
                id,
                data: Bytes::new(),
                done: tx,
            }));
            (id, rx)
        };
        let stream = Stream {
            id,
            shared: self.shared.clone(),
            write: PollSender::new(self.write.clone()),
            receive: Some(receive),
            close: close.clone(),
            cancelled: Box::pin(close.cancelled_owned()),
            remote_fin,
            pending: None,
            pending_is_flush: false,
            dirty: false,
            data: Bytes::new(),
            receive_permit: None,
            flow,
            since_update: 0,
        };
        // Cancellation drops the newly registered logical stream and queues FIN.
        done.await.map_err(|_| io::ErrorKind::ConnectionAborted)??;
        Ok(Box::new(stream))
    }
}
struct Lifetime(Arc<Shared>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.closed = true;
        for (_, entry) in state.streams.drain() {
            entry.close.cancel();
            entry.flow.changed.wake();
        }
    }
}
pub(crate) fn new(raw: BoxStream) -> (Client, impl Future<Output = ()> + Send) {
    with_options(raw, Options::default()).expect("valid default smux options")
}
#[cfg(any(feature = "sing-mux", test))]
pub(crate) fn new_with_autonomous_writes(
    raw: BoxStream,
    autonomous_writes: bool,
) -> (Client, impl Future<Output = ()> + Send) {
    configure(raw, Options::default(), autonomous_writes).expect("valid default smux options")
}
pub(crate) fn with_options(
    raw: BoxStream,
    options: Options,
) -> io::Result<(Client, impl Future<Output = ()> + Send)> {
    configure(raw, options, false)
}
fn configure(
    raw: BoxStream,
    options: Options,
    autonomous_writes: bool,
) -> io::Result<(Client, impl Future<Output = ()> + Send)> {
    if !(1..=2).contains(&options.version)
        || !(1..=65535).contains(&options.frame_size)
        || options.receive_buffer == 0
        || options.receive_buffer > 8 * 1024 * 1024
        || options.stream_buffer == 0
        || options.stream_buffer > options.receive_buffer
        || options.keepalive.is_some_and(|d| d.is_zero())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let receive_budget = Arc::new(tokio::sync::Semaphore::new(options.receive_buffer));
    let epoch = tokio::time::Instant::now();
    let last_read = Arc::new(AtomicU64::new(0));
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            closed: false,
            next: 1,
            streams: HashMap::new(),
        }),
        changed: Notify::new(),
        options,
        autonomous_writes,
    });
    let lifetime = Lifetime(shared.clone());
    let (write, mut frames) = mpsc::channel::<Command>(crate::limits::SING_MUX_COMMAND_QUEUE);
    let client = Client {
        shared: shared.clone(),
        write,
    };
    let (mut reader, mut writer) = tokio::io::split(raw);
    let read_shared = shared.clone();
    let read_last = last_read.clone();
    let read = async move {
        let mut processed = 0;
        loop {
            if processed == crate::limits::IO_POLL_BUDGET {
                processed = 0;
                tokio::task::yield_now().await;
            }
            processed += 1;
            let mut header = [0; 8];
            reader.read_exact(&mut header).await?;
            let cmd = header[1];
            let length = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
            let id = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if header[0] != options.version
                || !matches!(cmd, 1..=4)
                || (cmd == 4 && (options.version != 2 || length != 8))
                || (matches!(cmd, 1 | 3) && length != 0)
            {
                return Err::<(), _>(io::Error::from(io::ErrorKind::InvalidData));
            }
            read_last.store(epoch.elapsed().as_millis() as u64, Ordering::Release);
            if cmd == 4 {
                let mut update = [0; 8];
                reader.read_exact(&mut update).await?;
                if let Some(entry) = read_shared.state.lock().unwrap().streams.get(&id) {
                    let consumed = u32::from_le_bytes(update[..4].try_into().unwrap());
                    let window = u32::from_le_bytes(update[4..].try_into().unwrap());
                    if window > i32::MAX as u32
                        || entry
                            .flow
                            .written
                            .load(Ordering::Acquire)
                            .wrapping_sub(consumed)
                            > i32::MAX as u32
                    {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    entry.flow.peer_consumed.store(consumed, Ordering::Release);
                    entry.flow.peer_window.store(window, Ordering::Release);
                    entry.flow.changed.wake();
                }
                continue;
            }
            if cmd == 1 {
                if let Some(entry) = read_shared.state.lock().unwrap().streams.remove(&id) {
                    entry.remote_fin.store(true, Ordering::Release);
                    entry.flow.changed.wake();
                }
                continue;
            }
            if cmd == 3 || length == 0 {
                tokio::task::yield_now().await;
                continue;
            }
            if length > options.stream_buffer || length > options.receive_buffer {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let permit = receive_budget
                .clone()
                .acquire_many_owned(receive_charge(length, options.receive_buffer) as u32)
                .await
                .map_err(|_| io::ErrorKind::ConnectionAborted)?;
            let mut data = vec![0; length];
            reader.read_exact(&mut data).await?;
            let target = read_shared
                .state
                .lock()
                .unwrap()
                .streams
                .get(&id)
                .map(|e| (e.receive.clone(), e.close.clone()));
            if let Some((receive, close)) = target {
                tokio::select! {biased;()=close.cancelled()=>{},_=receive.send(Packet {data:data.into(),_permit:permit})=>{}}
            }
        }
    };
    let write = async move {
        let mut processed = 0;
        // Keep only completion senders, never a second payload queue.
        let mut completions = Vec::with_capacity(crate::limits::SING_MUX_COMMAND_QUEUE);
        let duration = options
            .keepalive
            .unwrap_or(std::time::Duration::from_secs(24 * 3600));
        let mut keepalive =
            tokio::time::interval_at(tokio::time::Instant::now() + duration, duration);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // A canceled stream always has a FIN path even if the data queue is
            // full. No unbounded "control queue" and no try_send/drop fallback.
            let closing = {
                let mut state = shared.state.lock().unwrap();
                let id = state
                    .streams
                    .iter()
                    .find(|(_, e)| e.close.is_cancelled())
                    .map(|(id, _)| *id);
                id.and_then(|id| state.streams.remove(&id).map(|_| id))
            };
            if let Some(id) = closing {
                send(&mut writer, options.version, 1, id, &[]).await?;
            } else if options.version == 2 && {
                let update = {
                    let state = shared.state.lock().unwrap();
                    state.streams.iter().find_map(|(id, e)| {
                        e.flow
                            .update
                            .swap(false, Ordering::AcqRel)
                            .then(|| (*id, e.flow.consumed.load(Ordering::Acquire)))
                    })
                };
                if let Some((id, consumed)) = update {
                    let mut data = [0; 8];
                    data[..4].copy_from_slice(&consumed.to_le_bytes());
                    data[4..].copy_from_slice(&(options.stream_buffer as u32).to_le_bytes());
                    send(&mut writer, options.version, 4, id, &data).await?;
                    true
                } else {
                    false
                }
            } {
            } else {
                let frame = tokio::select! {
                    ()=shared.changed.notified()=>continue,
                    _=keepalive.tick(),if options.keepalive.is_some()=>{
                        if epoch.elapsed().as_millis() as u64-last_read.load(Ordering::Acquire)>3*duration.as_millis() as u64 {return Err(io::ErrorKind::TimedOut.into());}
                        send(&mut writer,options.version,3,0,&[]).await?;continue;
                    },
                    frame=frames.recv()=>{let Some(frame)=frame else {return Ok::<(),io::Error>(());};frame}
                };
                let mut command = frame;
                let mut count = 0;
                let mut bytes = 0_usize;
                let mut result = Ok(());
                loop {
                    let mut flush_barrier = false;
                    match command {
                        Command::Flush(done) => {
                            // FIFO after all earlier DATA writes. Its receiver
                            // remains in Stream even if a flush future is dropped.
                            completions.push(done);
                            flush_barrier = true;
                        }
                        Command::Frame(Frame {
                            cmd,
                            id,
                            data,
                            done,
                        }) => {
                            let alive = shared
                                .state
                                .lock()
                                .unwrap()
                                .streams
                                .get(&id)
                                .is_some_and(|entry| !entry.close.is_cancelled());
                            if alive {
                                bytes += 8 + data.len();
                                result =
                                    write_frame(&mut writer, options.version, cmd, id, &data).await;
                                if autonomous_writes && cmd == 2 {
                                    // This capability is restricted to owned
                                    // XHTTP drivers that advance accepted bodies
                                    // independently. It never weakens explicit flush.
                                    let _ = done.send(match &result {
                                        Ok(()) => Ok(()),
                                        Err(error) => Err(error.kind().into()),
                                    });
                                } else {
                                    completions.push(done);
                                }
                            } else {
                                let _ = done.send(Err(io::ErrorKind::BrokenPipe.into()));
                            }
                            // No second payload queue: at most the original
                            // command queue plus the currently written frame.
                            drop(data);
                        }
                    }
                    count += 1;
                    let control_pending = {
                        let state = shared.state.lock().unwrap();
                        state.streams.values().any(|entry| {
                            entry.close.is_cancelled()
                                || (options.version == 2
                                    && entry.flow.update.load(Ordering::Acquire))
                        })
                    };
                    if flush_barrier
                        || result.is_err()
                        || count == crate::limits::SING_MUX_COMMAND_QUEUE
                        || processed + count >= crate::limits::IO_POLL_BUDGET
                        || bytes + 8 + options.frame_size > 64 * 1024
                        || control_pending
                    {
                        break;
                    }
                    match frames.try_recv() {
                        Ok(next) => command = next,
                        Err(_) => break,
                    }
                }
                if result.is_ok() && !completions.is_empty() {
                    result = writer.flush().await;
                }
                let error = result.err().map(|error| error.kind());
                for done in completions.drain(..) {
                    let _ = done.send(match error {
                        Some(kind) => Err(kind.into()),
                        None => Ok(()),
                    });
                }
                if error.is_some() {
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
                processed += count;
                if processed >= crate::limits::IO_POLL_BUDGET {
                    processed = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }
            processed += 1;
            if processed >= crate::limits::IO_POLL_BUDGET {
                processed = 0;
                tokio::task::yield_now().await;
            }
        }
    };
    let driver = async move {
        let _lifetime = lifetime;
        tokio::select! {
            _=read=>{},
            _=write=>{}
        }
    };
    Ok((client, driver))
}
async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    cmd: u8,
    id: u32,
    data: &[u8],
) -> io::Result<()> {
    write_frame(writer, version, cmd, id, data).await?;
    writer.flush().await
}
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    cmd: u8,
    id: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut header = [0; 8];
    header[0] = version;
    header[1] = cmd;
    header[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    header[4..8].copy_from_slice(&id.to_le_bytes());
    writer.write_all(&header).await?;
    writer.write_all(data).await
}
struct Stream {
    id: u32,
    shared: Arc<Shared>,
    write: PollSender<Command>,
    receive: Option<mpsc::Receiver<Packet>>,
    receive_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    flow: Arc<Flow>,
    since_update: u32,
    close: CancellationToken,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    remote_fin: Arc<AtomicBool>,
    pending: Option<oneshot::Receiver<io::Result<()>>>,
    pending_is_flush: bool,
    dirty: bool,
    data: Bytes,
}
impl Stream {
    fn stop(&mut self) {
        self.close.cancel();
        self.shared.changed.notify_one();
        self.pending.take();
        self.write.abort_send();
        self.receive.take();
        self.data = Bytes::new();
        self.receive_permit.take();
    }
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.stop();
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(pending) = &mut self.pending {
            ready!(Pin::new(pending).poll(cx)).map_err(|_| io::ErrorKind::BrokenPipe)??;
            self.pending = None;
            if self.pending_is_flush {
                self.pending_is_flush = false;
                self.dirty = false;
            }
        }
        Poll::Ready(Ok(()))
    }
    fn poll_flush_barrier(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.flush_pending(cx))?;
        if !self.shared.autonomous_writes || !self.dirty {
            return Poll::Ready(Ok(()));
        }
        ready!(self.write.poll_reserve(cx)).map_err(|_| io::ErrorKind::BrokenPipe)?;
        let (done, completed) = oneshot::channel();
        self.write
            .send_item(Command::Flush(done))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.pending = Some(completed);
        self.pending_is_flush = true;
        self.flush_pending(cx)
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.stop();
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.stop();
            return Poll::Ready(Ok(()));
        }
        if self.data.is_empty() {
            let Some(receive) = self.receive.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match ready!(receive.poll_recv(cx)) {
                Some(packet) => {
                    self.data = packet.data;
                    self.receive_permit = Some(packet._permit);
                }
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = out.remaining().min(self.data.len());
        out.put_slice(&self.data[..n]);
        self.data.advance(n);
        if self.data.is_empty() {
            // Advancing Bytes does not release its backing allocation. Retain
            // the whole admission permit until that allocation is dropped.
            self.data = Bytes::new();
            self.receive_permit.take();
        }
        if self.shared.options.version == 2 {
            let before = self.flow.consumed.fetch_add(n as u32, Ordering::AcqRel);
            self.since_update = self.since_update.wrapping_add(n as u32);
            if before == 0 || self.since_update as usize >= self.shared.options.stream_buffer / 2 {
                self.since_update = 0;
                self.flow.update.store(true, Ordering::Release);
                self.shared.changed.notify_one();
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.flush_pending(cx))?;
        self.flow.changed.register(cx.waker());
        if self.remote_fin.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let credit = if self.shared.options.version == 2 {
            self.flow.credit() as usize
        } else {
            usize::MAX
        };
        if credit == 0 {
            // A window-blocked flow must leave queue capacity for other streams.
            self.write.abort_send();
            return Poll::Pending;
        }
        ready!(self.write.poll_reserve(cx)).map_err(|_| io::ErrorKind::BrokenPipe)?;
        let size = buf.len().min(self.shared.options.frame_size).min(credit);
        let (tx, rx) = oneshot::channel();
        let id = self.id;
        self.flow.written.fetch_add(size as u32, Ordering::AcqRel);
        self.write
            .send_item(Command::Frame(Frame {
                cmd: 2,
                id,
                data: Bytes::copy_from_slice(&buf[..size]),
                done: tx,
            }))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.pending = Some(rx);
        self.dirty = true;
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_barrier(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.close.is_cancelled() {
            self.stop();
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_flush_barrier(cx))?;
        self.stop();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn metered_peer(
        options: Options,
    ) -> (
        Client,
        impl Future<Output = ()> + Send,
        tokio::io::DuplexStream,
        Arc<FlushGateState>,
    ) {
        let (raw, peer) = tokio::io::duplex(4096);
        let meter = Arc::new(FlushGateState::default());
        meter.mode.store(1, Ordering::Release);
        let (client, driver) = with_options(
            Box::new(FlushGate {
                raw,
                state: meter.clone(),
            }),
            options,
        )
        .expect("valid memory receive fixture options");
        (client, driver, peer, meter)
    }

    async fn drive_ready_once<F: Future<Output = ()>>(mut driver: Pin<&mut F>) -> io::Result<()> {
        let result = std::future::poll_fn(|cx| {
            let mut ready = std::pin::pin!(tokio::task::unconstrained(driver.as_mut()));
            Poll::Ready(ready.as_mut().poll(cx))
        })
        .await;
        if result.is_pending() {
            Ok(())
        } else {
            Err(io::Error::other("memory smux driver ended unexpectedly"))
        }
    }

    async fn open_memory_stream<F: Future<Output = ()>>(
        client: &Client,
        driver: Pin<&mut F>,
        peer: &mut tokio::io::DuplexStream,
    ) -> io::Result<(BoxStream, u32)> {
        let mut opening = Box::pin(client.open());
        if !futures_util::poll!(opening.as_mut()).is_pending() {
            return Err(io::Error::other("stream opened before its SYN was driven"));
        }
        drive_ready_once(driver).await?;
        let stream = opening.await?;
        let mut syn = [0; 8];
        peer.read_exact(&mut syn).await?;
        let id = u32::from_le_bytes(syn[4..].try_into().unwrap());
        if syn[..4] != [1, 0, 0, 0] || id % 2 != 1 {
            return Err(io::Error::other(
                "memory receive fixture saw an invalid SYN",
            ));
        }
        Ok((stream, id))
    }

    fn memory_frame(wire: &mut Vec<u8>, cmd: u8, id: u32, data: &[u8]) {
        wire.extend_from_slice(&[1, cmd]);
        wire.extend_from_slice(&(data.len() as u16).to_le_bytes());
        wire.extend_from_slice(&id.to_le_bytes());
        wire.extend_from_slice(data);
    }

    async fn read_memory<F: Future<Output = ()>>(
        stream: &mut BoxStream,
        mut driver: Pin<&mut F>,
        data: &mut [u8],
    ) -> io::Result<()> {
        let mut reading = Box::pin(stream.read_exact(data));
        std::future::poll_fn(|cx| {
            if let Poll::Ready(result) = reading.as_mut().poll(cx) {
                return Poll::Ready(result.map(|_| ()));
            }
            let mut ready = std::pin::pin!(tokio::task::unconstrained(driver.as_mut()));
            if ready.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::other(
                    "memory smux driver ended while reading",
                )));
            }
            reading.as_mut().poll(cx).map(|result| result.map(|_| ()))
        })
        .await
    }

    async fn read_once(stream: &mut BoxStream, data: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut reading = Box::pin(stream.read(data));
        futures_util::poll!(reading.as_mut())
    }

    async fn memory_peer_eof(peer: &mut tokio::io::DuplexStream) -> bool {
        // Drain only a bounded amount of existing SYN/FIN control output.
        let mut tail = Vec::new();
        let mut bounded = peer.take(4097);
        let ended =
            tokio::time::timeout(Duration::from_secs(2), bounded.read_to_end(&mut tail)).await;
        matches!(ended, Ok(Ok(_))) && tail.len() < 4097
    }

    #[tokio::test]
    async fn ready_data_reader_yields_within_one_io_poll_budget() {
        let (client, driver, mut peer, meter) = metered_peer(Options {
            frame_size: 16 * 1024,
            // Keep the legacy fixture wide enough not to mask missing fairness.
            stream_buffer: 2 * 1024 * 1024,
            ..Options::default()
        });
        let mut driver = Box::pin(driver);
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let (stream, id) = open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let mut wire = Vec::new();
            for value in 0..128_u8 {
                memory_frame(&mut wire, 2, id, &[value]);
            }
            peer.write_all(&wire).await?;
            let before = meter.read_bytes.load(Ordering::Acquire);
            drive_ready_once(driver.as_mut()).await?;
            let read_bytes = meter.read_bytes.load(Ordering::Acquire) - before;
            drop(stream);
            Ok::<_, io::Error>(read_bytes)
        })
        .await;
        drop(driver);
        let closed = client.shared.state.lock().unwrap().closed;
        let eof = memory_peer_eof(&mut peer).await;
        assert!(
            closed && eof,
            "reader fairness fixture did not close driver/peer"
        );
        let read_bytes = observed
            .expect("reader fairness fixture watchdog expired")
            .expect("reader fairness fixture failed before DATA observation");
        assert!(
            read_bytes >= 9,
            "reader fairness fixture did not advance DATA"
        );
        let frames_read = read_bytes / 9;
        assert!(
            frames_read <= crate::limits::IO_POLL_BUDGET,
            "ready smux DATA reader exceeded one IO poll budget: read {frames_read} complete frames"
        );
    }

    #[tokio::test]
    async fn unread_stream_does_not_block_sibling_data_and_fin() {
        let (client, driver, mut peer, _meter) = metered_peer(Options::default());
        let mut driver = Box::pin(driver);
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let (unread, first) = open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let (mut sibling, second) =
                open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let mut wire = Vec::new();
            for value in b"abcde" {
                memory_frame(&mut wire, 2, first, &[*value]);
            }
            memory_frame(&mut wire, 2, second, b"z");
            memory_frame(&mut wire, 1, second, &[]);
            peer.write_all(&wire).await?;
            drive_ready_once(driver.as_mut()).await?;
            let mut byte = [0];
            let progressed = match read_once(&mut sibling, &mut byte).await {
                Poll::Pending => false,
                Poll::Ready(Ok(1)) => true,
                _ => return Err(io::Error::other("sibling ended before its queued DATA")),
            };
            let eof = if progressed {
                matches!(read_once(&mut sibling, &mut [0]).await, Poll::Ready(Ok(0)))
            } else {
                false
            };
            drop((unread, sibling));
            Ok::<_, io::Error>((progressed, byte, eof))
        })
        .await;
        drop(driver);
        let closed = client.shared.state.lock().unwrap().closed;
        let eof = memory_peer_eof(&mut peer).await;
        assert!(closed && eof, "sibling fixture did not close driver/peer");
        let (progressed, byte, sibling_eof) = observed
            .expect("sibling fixture watchdog expired")
            .expect("sibling fixture failed before receive observation");
        assert!(!progressed || byte == *b"z", "sibling DATA content changed");
        assert!(
            progressed && sibling_eof,
            "unread smux stream blocked sibling DATA/FIN despite spare connection budget"
        );
    }

    #[tokio::test]
    async fn receive_storage_budget_bounds_tiny_frames_and_waits_for_full_consumption() {
        let quota = 512;
        let (client, driver, mut peer, meter) = metered_peer(Options {
            frame_size: 128,
            receive_buffer: quota,
            stream_buffer: quota,
            ..Options::default()
        });
        let mut driver = Box::pin(driver);
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let (mut stream, id) = open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let mut wire = Vec::new();
            for value in 0..256_usize {
                memory_frame(&mut wire, 2, id, &[value as u8]);
            }
            peer.write_all(&wire).await?;
            for _ in 0..16 {
                drive_ready_once(driver.as_mut()).await?;
            }
            let before = meter.read_bytes.load(Ordering::Acquire);
            drive_ready_once(driver.as_mut()).await?;
            let idle = meter.read_bytes.load(Ordering::Acquire);
            let mut byte = [0];
            read_memory(&mut stream, driver.as_mut(), &mut byte).await?;
            let mut valid = byte == [0];
            drive_ready_once(driver.as_mut()).await?;
            let after_one = meter.read_bytes.load(Ordering::Acquire);
            for expected in 1..256_usize {
                read_memory(&mut stream, driver.as_mut(), &mut byte).await?;
                valid &= byte == [expected as u8];
            }
            let mut next = Vec::new();
            memory_frame(&mut next, 2, id, &vec![b'p'; quota]);
            memory_frame(&mut next, 2, id, b"q");
            peer.write_all(&next).await?;
            for _ in 0..4 {
                drive_ready_once(driver.as_mut()).await?;
            }
            let before_partial = meter.read_bytes.load(Ordering::Acquire);
            read_memory(&mut stream, driver.as_mut(), &mut byte).await?;
            valid &= byte == *b"p";
            for _ in 0..4 {
                drive_ready_once(driver.as_mut()).await?;
            }
            let after_partial = meter.read_bytes.load(Ordering::Acquire);
            let mut rest = vec![0; quota - 1];
            read_memory(&mut stream, driver.as_mut(), &mut rest).await?;
            valid &= rest.iter().all(|value| *value == b'p');
            for _ in 0..4 {
                drive_ready_once(driver.as_mut()).await?;
            }
            let after_full = meter.read_bytes.load(Ordering::Acquire);
            read_memory(&mut stream, driver.as_mut(), &mut byte).await?;
            valid &= byte == *b"q";
            drop(stream);
            Ok::<_, io::Error>((
                valid,
                before,
                idle,
                after_one,
                wire.len(),
                before_partial,
                after_partial,
                after_full,
            ))
        })
        .await;
        drop(driver);
        let closed = client.shared.state.lock().unwrap().closed;
        let eof = memory_peer_eof(&mut peer).await;
        assert!(
            closed && eof,
            "receive budget fixture did not close driver/peer"
        );
        let (valid, before, idle, after_one, input, before_partial, after_partial, after_full) =
            observed
                .expect("receive budget fixture watchdog expired")
                .expect("receive budget fixture failed before observations");
        assert!(
            valid && before >= 9,
            "receive budget fixture changed or did not receive DATA"
        );
        let storage_floor = std::mem::size_of::<Packet>() + 1;
        let retained_before = before / 9;
        let retained_after = (after_one / 9).saturating_sub(1);
        assert!(
            before < input
                && idle == before
                && retained_before * storage_floor <= quota
                && retained_after * storage_floor <= quota,
            "small smux frames bypassed the connection receive storage budget"
        );
        assert!(
            after_one > before,
            "consuming a frame did not restore receive progress"
        );
        assert_eq!(
            after_partial, before_partial,
            "partially read smux frame returned its backing budget early"
        );
        assert!(
            after_full > after_partial,
            "draining a frame did not release its receive budget"
        );
    }

    #[tokio::test]
    async fn local_shutdown_releases_queued_budget_while_remote_fin_preserves_data() {
        let quota = 512;
        let (client, driver, mut peer, meter) = metered_peer(Options {
            frame_size: 128,
            receive_buffer: quota,
            stream_buffer: quota,
            ..Options::default()
        });
        let mut driver = Box::pin(driver);
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let (mut stopped, first) =
                open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let (mut remote, second) =
                open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let (mut next, third) = open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let mut wire = Vec::new();
            memory_frame(&mut wire, 2, first, &vec![b'a'; quota]);
            memory_frame(&mut wire, 2, second, &vec![b'b'; quota]);
            memory_frame(&mut wire, 1, second, &[]);
            memory_frame(&mut wire, 2, third, b"z");
            peer.write_all(&wire).await?;
            for _ in 0..4 {
                drive_ready_once(driver.as_mut()).await?;
            }
            let before = meter.read_bytes.load(Ordering::Acquire);
            stopped.shutdown().await?;
            for _ in 0..4 {
                drive_ready_once(driver.as_mut()).await?;
            }
            let after = meter.read_bytes.load(Ordering::Acquire);
            let fin_seen = !client
                .shared
                .state
                .lock()
                .unwrap()
                .streams
                .contains_key(&second);
            let mut byte = [0];
            let next_blocked = matches!(read_once(&mut next, &mut byte).await, Poll::Pending);
            let mut data_valid = false;
            let mut remote_eof = false;
            let mut next_ready = false;
            if fin_seen {
                let mut data = vec![0; quota];
                read_memory(&mut remote, driver.as_mut(), &mut data).await?;
                data_valid = data.iter().all(|value| *value == b'b');
                remote_eof = matches!(read_once(&mut remote, &mut [0]).await, Poll::Ready(Ok(0)));
                for _ in 0..4 {
                    drive_ready_once(driver.as_mut()).await?;
                }
                next_ready = matches!(read_once(&mut next, &mut byte).await, Poll::Ready(Ok(1)))
                    && byte == *b"z";
            }
            // Retain the shutdown stream throughout the release observation.
            drop((stopped, remote, next));
            Ok::<_, io::Error>((
                after > before && fin_seen,
                next_blocked,
                data_valid,
                remote_eof,
                next_ready,
            ))
        })
        .await;
        drop(driver);
        let closed = client.shared.state.lock().unwrap().closed;
        let eof = memory_peer_eof(&mut peer).await;
        assert!(
            closed && eof,
            "shutdown budget fixture did not close driver/peer"
        );
        let (released, blocked, valid, remote_eof, resumed) = observed
            .expect("shutdown budget fixture watchdog expired")
            .expect("shutdown budget fixture failed before observations");
        assert!(
            blocked,
            "remote FIN returned queued DATA budget before consumption"
        );
        assert!(
            released,
            "local smux shutdown retained queued budget while its stream was held"
        );
        assert!(
            valid && remote_eof,
            "remote FIN discarded queued DATA or failed to end after draining"
        );
        assert!(
            resumed,
            "draining the remote FIN stream did not restore sibling progress"
        );
    }

    #[tokio::test]
    async fn shutdown_after_driver_exit_releases_a_retained_stream_receiver() {
        let (client, driver, mut peer, _meter) = metered_peer(Options::default());
        let mut driver = Box::pin(driver);
        let setup = tokio::time::timeout(Duration::from_secs(2), async {
            let (stream, id) = open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
            let sender = client.shared.state.lock().unwrap().streams[&id]
                .receive
                .clone();
            let mut wire = Vec::new();
            memory_frame(&mut wire, 2, id, b"queued");
            peer.write_all(&wire).await?;
            drive_ready_once(driver.as_mut()).await?;
            Ok::<_, io::Error>((stream, sender))
        })
        .await;
        drop(driver);
        let closed = client.shared.state.lock().unwrap().closed;
        let eof = memory_peer_eof(&mut peer).await;
        let (mut stream, sender) = setup
            .expect("driver-exit fixture watchdog expired")
            .expect("driver-exit fixture failed before receive observation");
        let shutdown = tokio::time::timeout(Duration::from_secs(2), stream.shutdown()).await;
        let released = sender.is_closed();
        drop((stream, sender));
        assert!(
            closed && eof,
            "driver-exit fixture did not close driver/peer"
        );
        assert!(
            matches!(shutdown, Ok(Ok(()))),
            "cancelled stream shutdown did not complete"
        );
        assert!(
            released,
            "shutdown after driver exit retained its receive queue"
        );
    }

    #[tokio::test]
    async fn small_legal_receive_quotas_allow_a_whole_frame_and_continue() {
        for quota in [1, 63, 512] {
            let (client, driver, mut peer, meter) = metered_peer(Options {
                frame_size: quota,
                receive_buffer: quota,
                stream_buffer: quota,
                ..Options::default()
            });
            let mut driver = Box::pin(driver);
            let observed = tokio::time::timeout(Duration::from_secs(2), async {
                let (mut stream, id) =
                    open_memory_stream(&client, driver.as_mut(), &mut peer).await?;
                let mut wire = Vec::new();
                memory_frame(&mut wire, 2, id, &vec![b'a'; quota]);
                memory_frame(&mut wire, 2, id, &vec![b'b'; quota]);
                peer.write_all(&wire).await?;
                for _ in 0..4 {
                    drive_ready_once(driver.as_mut()).await?;
                }
                let before = meter.read_bytes.load(Ordering::Acquire);
                let mut first = vec![0; quota];
                read_memory(&mut stream, driver.as_mut(), &mut first).await?;
                for _ in 0..4 {
                    drive_ready_once(driver.as_mut()).await?;
                }
                let after = meter.read_bytes.load(Ordering::Acquire);
                let mut second = vec![0; quota];
                read_memory(&mut stream, driver.as_mut(), &mut second).await?;
                let valid = first.iter().all(|value| *value == b'a')
                    && second.iter().all(|value| *value == b'b');
                drop(stream);
                Ok::<_, io::Error>((before >= quota + 8, after > before, valid))
            })
            .await;
            drop(driver);
            let closed = client.shared.state.lock().unwrap().closed;
            let eof = memory_peer_eof(&mut peer).await;
            assert!(
                closed && eof,
                "small quota fixture did not close driver/peer"
            );
            let (received, resumed, valid) = observed
                .expect("small quota fixture watchdog expired")
                .expect("small quota fixture rejected or stalled a legal whole frame");
            assert!(
                received && resumed && valid,
                "legal smux receive quota {quota} did not progress"
            );
        }
    }

    #[derive(Default)]
    struct FlushGateState {
        // 0: blocked; 1: successful physical flush; 2: physical error.
        mode: std::sync::atomic::AtomicU8,
        flushes: std::sync::atomic::AtomicUsize,
        read_bytes: std::sync::atomic::AtomicUsize,
        changed: AtomicWaker,
    }
    struct FlushGate {
        raw: tokio::io::DuplexStream,
        state: Arc<FlushGateState>,
    }
    impl AsyncRead for FlushGate {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = out.filled().len();
            let result = Pin::new(&mut self.raw).poll_read(cx, out);
            let count = out.filled().len() - before;
            if count != 0 {
                self.state.read_bytes.fetch_add(count, Ordering::AcqRel);
            }
            result
        }
    }
    impl AsyncWrite for FlushGate {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.raw).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.state.changed.register(cx.waker());
            match self.state.mode.load(Ordering::Acquire) {
                0 => Poll::Pending,
                2 => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                _ => {
                    ready!(Pin::new(&mut self.raw).poll_flush(cx))?;
                    self.state.flushes.fetch_add(1, Ordering::AcqRel);
                    Poll::Ready(Ok(()))
                }
            }
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn autonomous_data_keeps_explicit_flush_strong_and_cancelled_barrier_unique() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (raw, mut peer) = tokio::io::duplex(1024);
            let gate = Arc::new(FlushGateState::default());
            gate.mode.store(1, Ordering::Release);
            let (client, driver) = new_with_autonomous_writes(
                Box::new(FlushGate {
                    raw,
                    state: gate.clone(),
                }),
                true,
            );
            let mut driver = Box::pin(driver);
            let mut opening = Box::pin(client.open());
            assert!(futures_util::poll!(opening.as_mut()).is_pending());
            assert!(futures_util::poll!(driver.as_mut()).is_pending());
            let mut stream = opening.await.unwrap();
            let mut syn = [0; 8];
            peer.read_exact(&mut syn).await.unwrap();
            assert_eq!(gate.flushes.load(Ordering::Acquire), 1);

            gate.mode.store(0, Ordering::Release);
            for payload in [b"one", b"two"] {
                stream.write_all(payload).await.unwrap();
                assert!(futures_util::poll!(driver.as_mut()).is_pending());
            }
            let mut wire = [0; 22];
            peer.read_exact(&mut wire).await.unwrap();
            assert_eq!(&wire[..4], &[1, 2, 3, 0]);
            assert_eq!(&wire[8..11], b"one");
            assert_eq!(&wire[11..15], &[1, 2, 3, 0]);
            assert_eq!(&wire[19..], b"two");
            assert_eq!(
                gate.flushes.load(Ordering::Acquire),
                1,
                "accepted DATA must not require a successful physical flush"
            );

            let mut first_flush = Box::pin(stream.flush());
            assert!(futures_util::poll!(first_flush.as_mut()).is_pending());
            assert!(futures_util::poll!(driver.as_mut()).is_pending());
            drop(first_flush);
            let mut resumed_flush = Box::pin(stream.flush());
            assert!(futures_util::poll!(resumed_flush.as_mut()).is_pending());
            assert_eq!(
                client.write.capacity(),
                crate::limits::SING_MUX_COMMAND_QUEUE,
                "retrying must retain the in-flight barrier, not queue another"
            );
            gate.mode.store(1, Ordering::Release);
            gate.changed.wake();
            assert!(futures_util::poll!(driver.as_mut()).is_pending());
            resumed_flush.await.unwrap();
            assert_eq!(gate.flushes.load(Ordering::Acquire), 2);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn autonomous_shutdown_orders_flush_before_fin_and_stop_releases_waiters() {
        tokio::time::timeout(Duration::from_secs(2), async {
            for outcome in [1, 2, 3] {
                let (raw, mut peer) = tokio::io::duplex(1024);
                let gate = Arc::new(FlushGateState::default());
                gate.mode.store(1, Ordering::Release);
                let (client, driver) = new_with_autonomous_writes(
                    Box::new(FlushGate {
                        raw,
                        state: gate.clone(),
                    }),
                    true,
                );
                let mut driver = Some(Box::pin(driver));
                let mut opening = Box::pin(client.open());
                assert!(futures_util::poll!(opening.as_mut()).is_pending());
                assert!(futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_pending());
                let mut stream = opening.await.unwrap();
                let mut syn = [0; 8];
                peer.read_exact(&mut syn).await.unwrap();
                gate.mode.store(0, Ordering::Release);
                stream.write_all(b"one").await.unwrap();
                assert!(futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_pending());
                let mut shutdown = Box::pin(stream.shutdown());
                assert!(futures_util::poll!(shutdown.as_mut()).is_pending());
                assert!(futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_pending());
                let mut frame = [0; 11];
                peer.read_exact(&mut frame).await.unwrap();
                assert_eq!(&frame[..4], &[1, 2, 3, 0]);
                assert_eq!(&frame[8..], b"one");
                {
                    let mut next = [0];
                    let reading = peer.read(&mut next);
                    tokio::pin!(reading);
                    assert!(
                        futures_util::poll!(reading.as_mut()).is_pending(),
                        "FIN must not overtake a pending explicit payload flush"
                    );
                }
                if outcome == 3 {
                    // This is the node owner's cancellation boundary: dropping
                    // its one driver closes both halves and all logical waiters.
                    drop(driver.take());
                } else {
                    gate.mode.store(outcome, Ordering::Release);
                    gate.changed.wake();
                    assert_eq!(
                        futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_ready(),
                        outcome == 2
                    );
                }
                let shutdown_result = shutdown.await;
                if outcome == 1 {
                    assert!(shutdown_result.is_ok());
                    assert!(futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_pending());
                    let mut fin = [0; 8];
                    peer.read_exact(&mut fin).await.unwrap();
                    assert_eq!(&fin[..4], &[1, 1, 0, 0]);
                    assert_eq!(&fin[4..], &syn[4..]);
                    assert_eq!(gate.flushes.load(Ordering::Acquire), 3);
                } else {
                    // Driver exit already cancels the stream, so shutdown
                    // may be idempotent while explicit flush still fails.
                    assert!(stream.flush().await.is_err());
                    assert!(client.shared.state.lock().unwrap().closed);
                    assert!(client.open().await.is_err());
                }
                drop(stream);
                drop(driver);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn concurrent_frames_share_one_real_flush_and_never_ack_early() {
        tokio::time::timeout(Duration::from_secs(2), async {
            // Exercise physical success, physical flush error and owner Stop
            // after all queued payloads have been written but not flushed.
            for outcome in [1, 2, 3] {
                let (raw, mut peer) = tokio::io::duplex(1024);
                let gate = Arc::new(FlushGateState::default());
                gate.mode.store(1, Ordering::Release);
                let (client, driver) = new(Box::new(FlushGate {
                    raw,
                    state: gate.clone(),
                }));
                let mut driver = Some(Box::pin(driver));
                let mut openings = (0..3).map(|_| Box::pin(client.open())).collect::<Vec<_>>();
                for opening in &mut openings {
                    assert!(futures_util::poll!(opening.as_mut()).is_pending());
                }
                assert!(futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_pending());
                let mut streams = Vec::new();
                for opening in openings {
                    streams.push(opening.await.unwrap());
                }
                assert_eq!(gate.flushes.load(Ordering::Acquire), 1);
                let mut syn = [0; 24];
                peer.read_exact(&mut syn).await.unwrap();
                for (index, header) in syn.chunks_exact(8).enumerate() {
                    assert_eq!(&header[..4], &[1, 0, 0, 0]);
                    assert_eq!(
                        u32::from_le_bytes(header[4..].try_into().unwrap()),
                        3 + index as u32 * 2
                    );
                }
                gate.mode.store(0, Ordering::Release);
                // The physical driver is not spawned: all three logical
                // writes are deterministically ready before it is polled.
                for stream in &mut streams {
                    stream.write_all(b"one").await.unwrap();
                }
                assert!(futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_pending());
                for stream in &mut streams {
                    let flush = stream.flush();
                    tokio::pin!(flush);
                    assert!(futures_util::poll!(flush.as_mut()).is_pending());
                }
                assert_eq!(gate.flushes.load(Ordering::Acquire), 1);
                let mut wire = [0; 33];
                peer.read_exact(&mut wire).await.unwrap();
                for (index, frame) in wire.chunks_exact(11).enumerate() {
                    assert_eq!(&frame[..4], &[1, 2, 3, 0]);
                    assert_eq!(
                        u32::from_le_bytes(frame[4..8].try_into().unwrap()),
                        3 + index as u32 * 2
                    );
                    assert_eq!(&frame[8..], b"one");
                }
                if outcome == 3 {
                    drop(driver.take());
                } else {
                    gate.mode.store(outcome, Ordering::Release);
                    gate.changed.wake();
                    assert_eq!(
                        futures_util::poll!(driver.as_mut().unwrap().as_mut()).is_ready(),
                        outcome == 2
                    );
                }
                for stream in &mut streams {
                    assert_eq!(stream.flush().await.is_ok(), outcome == 1);
                }
                assert_eq!(
                    gate.flushes.load(Ordering::Acquire),
                    if outcome == 1 { 2 } else { 1 }
                );
                if outcome != 1 {
                    assert!(client.open().await.is_err());
                }
                drop(streams);
                drop(driver);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_flushes_the_pending_frame_before_fin() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (raw, mut peer) = tokio::io::duplex(16);
            let (client, driver) = new(Box::new(raw));
            let task = tokio::spawn(driver);
            let mut stream = client.open().await.unwrap();
            let mut syn = [0; 8];
            peer.read_exact(&mut syn).await.unwrap();
            let receive = tokio::spawn(async move {
                let mut received = Vec::new();
                loop {
                    let mut header = [0; 8];
                    peer.read_exact(&mut header).await.unwrap();
                    assert_eq!(&header[4..], &syn[4..]);
                    if header[1] == 1 {
                        break;
                    }
                    assert_eq!(header[1], 2);
                    let size = u16::from_le_bytes([header[2], header[3]]) as usize;
                    let mut data = vec![0; size];
                    peer.read_exact(&mut data).await.unwrap();
                    received.extend(data);
                }
                received
            });
            let payload = vec![b'x'; 1024];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let received = receive.await.unwrap();
            task.await.unwrap();
            assert_eq!(received.len(), payload.len());
            assert_eq!(received, payload);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn malformed_smux_headers_close_the_owned_driver_before_reading_a_body() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "XHTTP-UNIT",
            "malformed_smux_headers_close_the_owned_driver_before_reading_a_body",
        );
        for (version, command, length) in [(2, 2, 0), (1, 0, 0), (1, 4, 0), (1, 1, 1), (1, 3, 1)] {
            tokio::time::timeout(Duration::from_secs(1), async {
                let (raw, mut peer) = tokio::io::duplex(64);
                let (client, driver) = new(Box::new(raw));
                let task = tokio::spawn(driver);
                let mut logical = client.open().await.unwrap();
                let mut syn = [0; 8];
                peer.read_exact(&mut syn).await.unwrap();
                assert_eq!(syn, [1, 0, 0, 0, 3, 0, 0, 0]);
                // No body is supplied: malformed control framing must terminate
                // immediately rather than waiting for attacker-controlled data.
                peer.write_all(&[version, command, length, 0, 3, 0, 0, 0])
                    .await
                    .unwrap();
                task.await.unwrap();
                assert_eq!(logical.read(&mut [0]).await.unwrap(), 0);
                assert!(logical.write_all(b"closed").await.is_err());
                assert!(client.open().await.is_err());
            })
            .await
            .unwrap();
        }
    }
}

#[cfg(test)]
mod version_two_tests {
    use super::*;
    #[tokio::test]
    async fn v2_zero_credit_streams_leave_shared_send_capacity_available() {
        use std::{future::poll_fn, time::Duration};
        fn frame(command: u8, id: u32, data: &[u8]) -> Vec<u8> {
            let mut wire = vec![2, command];
            wire.extend_from_slice(&(data.len() as u16).to_le_bytes());
            wire.extend_from_slice(&id.to_le_bytes());
            wire.extend_from_slice(data);
            wire
        }
        let (raw, mut peer) = tokio::io::duplex(64 * 1024);
        let (client, driver) = with_options(
            Box::new(raw),
            Options {
                version: 2,
                ..Default::default()
            },
        )
        .unwrap();
        let mut driver = tokio::spawn(driver);
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut streams = Vec::new();
            let mut ids = Vec::new();
            for _ in 0..=crate::limits::SING_MUX_COMMAND_QUEUE {
                streams.push(client.open().await?);
                let mut syn = [0; 8];
                peer.read_exact(&mut syn).await?;
                ids.push(u32::from_le_bytes(syn[4..].try_into().unwrap()));
            }
            let mut healthy = streams.pop().unwrap();
            let normal_id = *ids.last().unwrap();
            for &id in &ids[..streams.len()] {
                peer.write_all(&frame(4, id, &[0; 8])).await?;
            }
            // Reading a later PSH proves all preceding zero-window UPDs parsed.
            peer.write_all(&frame(2, normal_id, b"r")).await?;
            let mut marker = [0];
            healthy.read_exact(&mut marker).await?;
            let mut update = [0; 16];
            peer.read_exact(&mut update).await?; // Drain the marker's own UPD.
            let mut held: Vec<_> = streams
                .iter_mut()
                .map(|stream| Box::pin(stream.write_all(b"x")))
                .collect();
            let all_pending = poll_fn(|cx| {
                Poll::Ready(
                    held.iter_mut()
                        .map(|write| write.as_mut().poll(cx).is_pending())
                        .all(|p| p),
                )
            })
            .await;
            let normal = tokio::time::timeout(Duration::from_millis(150), async {
                healthy.write_all(b"h").await?;
                healthy.flush().await?;
                let mut wire = [0; 9];
                peer.read_exact(&mut wire).await?;
                Ok::<_, io::Error>(wire)
            })
            .await;
            // A real UPD must still wake and permit a previously blocked writer.
            peer.write_all(&frame(4, ids[0], &[0, 0, 0, 0, 1, 0, 0, 0]))
                .await?;
            let restored = tokio::time::timeout(Duration::from_millis(150), async {
                held[0].as_mut().await?;
                let mut wire = [0; 9];
                peer.read_exact(&mut wire).await?;
                Ok::<_, io::Error>(wire)
            })
            .await;
            // Invalid peer framing ends the actual driver and wakes zero-credit writers.
            peer.write_all(&[9, 0, 0, 0, 0, 0, 0, 0]).await?;
            let stopped = tokio::time::timeout(Duration::from_millis(150), held[1].as_mut()).await;
            drop(held);
            drop(streams);
            drop(healthy);
            Ok::<_, io::Error>((
                all_pending,
                marker,
                update,
                normal,
                restored,
                stopped,
                frame(2, normal_id, b"h"),
                frame(2, ids[0], b"x"),
            ))
        })
        .await;
        // Both timeout/error paths drop held writes and streams before joining.
        drop(client);
        drop(peer);
        let joined = tokio::time::timeout(Duration::from_secs(1), &mut driver).await;
        if joined.is_err() {
            driver.abort();
            let _ = driver.await;
        }
        assert!(
            joined.is_ok_and(|result| result.is_ok()),
            "smux driver did not join"
        );
        let (pending, marker, update, normal, restored, stopped, expected, resumed) = result
            .expect("memory fixture timed out")
            .expect("memory fixture IO failed");
        assert!(pending, "zero-window writes were unexpectedly accepted");
        assert_eq!(&marker, b"r");
        assert_eq!(&update[..2], &[2, 4]);
        assert_eq!(
            normal
                .expect("healthy stream blocked by zero-credit streams")
                .unwrap()
                .as_slice(),
            expected
        );
        assert_eq!(
            restored
                .expect("UPD did not wake the blocked writer")
                .unwrap()
                .as_slice(),
            resumed
        );
        assert!(
            matches!(stopped, Ok(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe),
            "driver close did not reject a zero-credit write"
        );
    }
    #[tokio::test]
    async fn v2_updates_open_credit_and_acknowledge_consumed_bytes() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (raw, mut peer) = tokio::io::duplex(31);
            let (client, driver) = with_options(
                Box::new(raw),
                Options {
                    version: 2,
                    ..Default::default()
                },
            )
            .unwrap();
            let driver = tokio::spawn(driver);
            let mut stream = client.open().await.unwrap();
            let mut syn = [0; 8];
            peer.read_exact(&mut syn).await.unwrap();
            assert_eq!(syn, [2, 0, 0, 0, 3, 0, 0, 0]);
            peer.write_all(&[2, 4, 8, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0])
                .await
                .unwrap();
            tokio::task::yield_now().await;
            assert_eq!(stream.write(b"payload").await.unwrap(), 4);
            let mut sent = [0; 12];
            peer.read_exact(&mut sent).await.unwrap();
            assert_eq!(&sent[8..], b"payl");
            stream.flush().await.unwrap();
            peer.write_all(&[2, 2, 3, 0, 3, 0, 0, 0, b'a', b'c', b'k'])
                .await
                .unwrap();
            let mut read = [0; 3];
            stream.read_exact(&mut read).await.unwrap();
            assert_eq!(&read, b"ack");
            let mut update = [0; 16];
            peer.read_exact(&mut update).await.unwrap();
            assert_eq!(&update[..8], &[2, 4, 8, 0, 3, 0, 0, 0]);
            assert_eq!(&update[8..12], &3u32.to_le_bytes());
            drop(stream);
            drop(client);
            drop(peer);
            driver.await.unwrap();
        })
        .await
        .unwrap();
    }
}
