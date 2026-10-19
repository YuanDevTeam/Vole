//! Independent smux v1 client framing. One owned reader/writer pair, bounded
//! physical write queue and per-stream receive queues; no detached workers.
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
            receive_buffer: 4 * 1024 * 1024,
            stream_buffer: crate::limits::SMUX_RECEIVE_QUEUE * crate::limits::SING_MUX_CHUNK,
            keepalive: None,
        }
    }
}
struct Packet {
    data: Bytes,
    _permit: tokio::sync::OwnedSemaphorePermit,
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
}
#[derive(Clone)]
pub(crate) struct Client {
    shared: Arc<Shared>,
    write: mpsc::Sender<Frame>,
}
impl Client {
    pub(crate) async fn open(&self) -> io::Result<BoxStream> {
        let permit = self
            .write
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| io::ErrorKind::ConnectionAborted)?;
        let capacity =
            (self.shared.options.stream_buffer / self.shared.options.frame_size).clamp(1, 256);
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
            permit.send(Frame {
                cmd: 0,
                id,
                data: Bytes::new(),
                done: tx,
            });
            (id, rx)
        };
        let stream = Stream {
            id,
            shared: self.shared.clone(),
            write: PollSender::new(self.write.clone()),
            receive,
            close: close.clone(),
            cancelled: Box::pin(close.cancelled_owned()),
            remote_fin,
            pending: None,
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
pub(crate) fn with_options(
    raw: BoxStream,
    options: Options,
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
    });
    let lifetime = Lifetime(shared.clone());
    let (write, mut frames) = mpsc::channel::<Frame>(crate::limits::SING_MUX_COMMAND_QUEUE);
    let client = Client {
        shared: shared.clone(),
        write,
    };
    let (mut reader, mut writer) = tokio::io::split(raw);
    let read_shared = shared.clone();
    let read_last = last_read.clone();
    let read = async move {
        loop {
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
                .acquire_many_owned(length as u32)
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
                let alive = shared
                    .state
                    .lock()
                    .unwrap()
                    .streams
                    .get(&frame.id)
                    .is_some_and(|e| !e.close.is_cancelled());
                if !alive {
                    let _ = frame.done.send(Err(io::ErrorKind::BrokenPipe.into()));
                    continue;
                }
                let result = send(
                    &mut writer,
                    options.version,
                    frame.cmd,
                    frame.id,
                    &frame.data,
                )
                .await;
                let failed = result.is_err();
                let _ = frame.done.send(result);
                if failed {
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
            }
            processed += 1;
            if processed == crate::limits::IO_POLL_BUDGET {
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
    let mut header = [0; 8];
    header[0] = version;
    header[1] = cmd;
    header[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    header[4..8].copy_from_slice(&id.to_le_bytes());
    writer.write_all(&header).await?;
    writer.write_all(data).await?;
    writer.flush().await
}
struct Stream {
    id: u32,
    shared: Arc<Shared>,
    write: PollSender<Frame>,
    receive: mpsc::Receiver<Packet>,
    receive_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    flow: Arc<Flow>,
    since_update: u32,
    close: CancellationToken,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    remote_fin: Arc<AtomicBool>,
    pending: Option<oneshot::Receiver<io::Result<()>>>,
    data: Bytes,
}
impl Stream {
    fn stop(&mut self) {
        self.close.cancel();
        self.shared.changed.notify_one();
        self.pending.take();
        self.write.abort_send();
        self.receive.close();
        self.data = Bytes::new();
        self.receive_permit.take();
    }
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(pending) = &mut self.pending {
            ready!(Pin::new(pending).poll(cx)).map_err(|_| io::ErrorKind::BrokenPipe)??;
            self.pending = None;
        }
        Poll::Ready(Ok(()))
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
        if out.remaining() == 0 || self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        if self.data.is_empty() {
            match ready!(self.receive.poll_recv(cx)) {
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
        if let Some(permit) = &mut self.receive_permit {
            drop(permit.split(n));
        }
        if self.data.is_empty() {
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
            .send_item(Frame {
                cmd: 2,
                id,
                data: Bytes::copy_from_slice(&buf[..size]),
                done: tx,
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.pending = Some(rx);
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_pending(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.close.is_cancelled() {
            return Poll::Ready(Ok(()));
        }
        ready!(self.flush_pending(cx))?;
        self.stop();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
