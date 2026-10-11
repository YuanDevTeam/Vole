//! SOCKS UDP datagrams carried inside Mieru's packet-over-stream envelope.
use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest, EstablishContext},
    resources::observation::{self, ResourceKind},
    session::{Datagram, Destination},
    socks5,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, WriteHalf},
    sync::mpsc,
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub(super) struct PacketTransport {
    writer: Option<WriteHalf<BoxStream>>,
    responses: mpsc::Receiver<io::Result<Datagram>>,
    cancel: CancellationToken,
    reader: Option<JoinHandle<()>>,
    alive: Arc<AtomicBool>,
    resolution: ResolutionContext,
    budget: DatagramBudget,
    closed: bool,
    _observation: observation::Guard,
}
impl PacketTransport {
    pub fn new<F>(
        io: BoxStream,
        request: &DatagramRequest,
        context: &EstablishContext,
        parent: CancellationToken,
        spawn: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(BoxFuture<'static, ()>) -> io::Result<JoinHandle<()>>,
    {
        if parent.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let cancel = parent.child_token();
        let (read, writer) = tokio::io::split(io);
        let (send, responses) = mpsc::channel(1);
        let alive = Arc::new(AtomicBool::new(true));
        let life = ReaderLife(alive.clone());
        let reader = spawn(Box::pin(read_loop(
            read,
            send,
            request.budget().receive(),
            cancel.clone(),
            life,
        )))?;
        Ok(Self {
            writer: Some(writer),
            responses,
            cancel,
            reader: Some(reader),
            alive,
            resolution: context.resolution(),
            budget: request.budget(),
            closed: false,
            _observation: observation::track(ResourceKind::Association),
        })
    }
    fn check(&self) -> Result<(), DispatchError> {
        if self.closed || self.cancel.is_cancelled() || !self.alive.load(Ordering::Acquire) {
            Err(DispatchError::NotAllowed)
        } else {
            Ok(())
        }
    }
}
struct ReaderLife(Arc<AtomicBool>);
impl Drop for ReaderLife {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct SendGuard<'a> {
    writer: &'a mut Option<WriteHalf<BoxStream>>,
    cancel: CancellationToken,
    committed: bool,
}
impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.cancel.cancel();
            self.writer.take();
        }
    }
}
#[async_trait]
impl DatagramTransport for PacketTransport {
    fn payload_budget(&self, remote: &Destination) -> DatagramBudget {
        let overhead = 3 + socks5::encoded_address_size(remote)
            .unwrap_or(usize::from(socks5::MAX_UDP_HEADER_SIZE));
        let transmit = usize::from(self.budget.transmit())
            .min(usize::from(u16::MAX).saturating_sub(overhead)) as u16;
        DatagramBudget::new(transmit, self.budget.receive())
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.check()?;
        if datagram.payload.len() > usize::from(self.payload_budget(&datagram.remote).transmit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mieru UDP payload exceeds send budget",
            )
            .into());
        }
        let remote = tokio::select! {biased;()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),result=self.resolution.resolve_ip(&datagram.remote,Instant::now()+DEFAULT_ESTABLISH_TIMEOUT)=>result?};
        let body = socks5::encode_udp_packet(
            &Destination::Ip(remote),
            &datagram.payload,
            usize::from(u16::MAX),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Mieru UDP packet"))?;
        let mut packet = Vec::with_capacity(body.len() + 4);
        packet.push(0);
        packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&body);
        packet.push(255);
        let mut guard = SendGuard {
            writer: &mut self.writer,
            cancel: self.cancel.clone(),
            committed: false,
        };
        tokio::select! {biased;()=guard.cancel.cancelled()=>return Err(DispatchError::NotAllowed),result=async {let writer=guard.writer.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;writer.write_all(&packet).await?;writer.flush().await}=>result?};
        guard.committed = true;
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.check()?;
        let result = tokio::select! {biased;()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),result=self.responses.recv()=>result};
        result
            .ok_or_else(|| DispatchError::from(io::Error::from(io::ErrorKind::UnexpectedEof)))?
            .map_err(DispatchError::from)
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed = true;
        self.cancel.cancel();
        self.writer.take();
        self.responses.close();
        while self.responses.try_recv().is_ok() {}
        if let Some(reader) = self.reader.take() {
            reader
                .await
                .map_err(|_| io::Error::other("Mieru UDP reader stopped"))?;
        }
        Ok(())
    }
}
impl Drop for PacketTransport {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.writer.take();
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }
}
async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    send: mpsc::Sender<io::Result<Datagram>>,
    maximum: u16,
    cancel: CancellationToken,
    _life: ReaderLife,
) {
    let reading = async {
        loop {
            let response = read_packet(&mut reader, maximum).await;
            let failed = response.is_err();
            if send.send(response).await.is_err() || failed {
                break;
            }
        }
    };
    tokio::select! {biased;()=cancel.cancelled()=>{},()=reading=>{}}
}
async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R, maximum: u16) -> io::Result<Datagram> {
    if reader.read_u8().await? != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = reader.read_u16().await? as usize;
    let max_wire = (usize::from(maximum) + usize::from(socks5::MAX_UDP_HEADER_SIZE))
        .min(usize::from(u16::MAX));
    if length > max_wire {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mieru UDP response exceeds receive budget",
        ));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    if reader.read_u8().await? != 255 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let (remote, payload) = socks5::decode_udp_packet(&body, max_wire)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Mieru UDP response"))?;
    if payload.len() > usize::from(maximum) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Datagram {
        remote,
        payload: Bytes::copy_from_slice(payload),
        sniffed_domain: None,
    })
}
