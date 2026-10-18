//! One bounded mKCP stream over an already controlled UDP transport.
//! No socket factory, DNS fallback, global session pool or detached owner.
mod state;
mod wire;
use crate::{
    config::MkcpOptions,
    dispatch::{BoxStream, DatagramTransport},
    resources::observation,
    session::{Datagram, Destination},
};
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::{Instant, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Default)]
struct Shared {
    acked: AtomicU64,
    closed: AtomicBool,
    writer: AtomicWaker,
}
struct Finish(Arc<Shared>);
impl Drop for Finish {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.writer.wake();
    }
}
struct Stream {
    io: DuplexStream,
    cancel: CancellationToken,
    shared: Arc<Shared>,
    written: u64,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        match Pin::new(&mut self.io).poll_write(cx, bytes) {
            Poll::Ready(Ok(n)) => {
                self.written = self.written.saturating_add(n as u64);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.writer.register(cx.waker());
        if self.shared.acked.load(Ordering::Acquire) >= self.written {
            return Poll::Ready(Ok(()));
        }
        if self.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Caller serializes this registration with the node's begin_shutdown admission.
pub(crate) fn connect(
    mut transport: Box<dyn DatagramTransport>,
    peer: std::net::SocketAddr,
    options: MkcpOptions,
    cancel: CancellationToken,
    tasks: &TaskTracker,
) -> io::Result<BoxStream> {
    let peer = Destination::Ip(peer);
    let budget = transport.payload_budget(&peer);
    let mtu = usize::from(options.mtu.min(budget.transmit()));
    let receive_limit = usize::from(options.peer_receive_limit().min(budget.receive()));
    let pipe = (usize::from(options.mtu) * 2).min(4096);
    let shared = Arc::new(Shared::default());
    let state = state::State::new(options.clone(), mtu, receive_limit, pipe, shared.clone())?;
    let codec = wire::Codec::new(&options)?;
    let (app, driver) = tokio::io::duplex(pipe);
    let token = cancel.clone();
    let finished = Finish(shared.clone());
    tasks.spawn(observation::task(async move {
        let _finished = finished;
        let _ = drive(
            &mut *transport,
            peer,
            driver,
            state,
            codec,
            receive_limit,
            &token,
        )
        .await;
        let _ = transport.close().await;
    }));
    Ok(Box::new(Stream {
        io: app,
        cancel,
        shared,
        written: 0,
    }))
}

async fn send(
    transport: &mut dyn DatagramTransport,
    packet: Datagram,
    cancel: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {biased;()=cancel.cancelled()=>Err(io::ErrorKind::Interrupted.into()),sent=timeout(Duration::from_secs(1),transport.send(packet))=>sent.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?.map_err(io::Error::other)}
}
async fn drive(
    transport: &mut dyn DatagramTransport,
    peer: Destination,
    pipe: DuplexStream,
    mut state: state::State,
    mut codec: wire::Codec,
    receive_limit: usize,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let (mut app_read, mut app_write) = tokio::io::split(pipe);
    let mut input = vec![0u8; state.mss];
    let mut sent = false;
    let mut pending = None;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if state.expired(now) || state.finished() {
            break;
        }
        if pending.is_none() {
            pending = state
                .next(now)
                .map(|segment| codec.seal(&segment))
                .transpose()?;
        }
        let capacity = state.read_capacity();
        let delivery = state.ready.front().cloned();
        tokio::select! {
            ()=cancel.cancelled()=>break,
            result=async {app_write.write(delivery.as_ref().unwrap()).await},if delivery.is_some()=>{
                let n=result?;if n==0{break;}state.delivered(n);
            },
            packet=transport.receive(),if sent=>{
                let packet=packet.map_err(io::Error::other)?;
                if packet.remote!=peer||packet.payload.len()>receive_limit{continue;}
                let Ok(plain)=codec.open(&packet.payload,receive_limit) else{continue;};
                let mut cursor=0;let mut count=0;
                while cursor<plain.len(){
                    let Some((segment,size))=wire::parse(&plain[cursor..],state.conv) else{break;};
                    state.input(segment,Instant::now());cursor+=size;count+=1;
                    if count%crate::limits::IO_POLL_BUDGET==0{tokio::task::yield_now().await;if cancel.is_cancelled(){break;}}
                }
            },
            n=app_read.read(&mut input[..capacity]),if capacity>0=>{
                let n=n?;if n==0{state.app_end=true;}else{state.queue(&input[..n]);}
            },
            ()=std::future::ready(()),if pending.is_some()=>{
                let packet=Datagram {remote:peer.clone(),payload:Bytes::from(pending.take().unwrap()),sniffed_domain:None};
                send(transport,packet,cancel).await?;sent=true;
            },
            ()=tokio::time::sleep_until(state.tick_at())=>{},
        }
    }
    // No delayed graceful-close task survives its stream/node. One bounded
    // best-effort termination also covers Drop/cancellation and forged peers.
    if sent && let Ok(bytes) = codec.seal(&state.terminate()) {
        let _ = timeout(
            Duration::from_millis(20),
            transport.send(Datagram {
                remote: peer,
                payload: Bytes::from(bytes),
                sniffed_domain: None,
            }),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
