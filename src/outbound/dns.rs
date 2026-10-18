//! A functional DNS route reusing the running session's resolver.
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::{
        MAX_MESSAGE_SIZE,
        runtime::{DnsWireResponse, RuntimeDns, RuntimeDnsError},
    },
    session::{Datagram, Destination, StreamSession},
};

use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};

const TCP_DNS_DUPLEX_CAPACITY: usize = 8 * 1024;
const DATAGRAM_QUEUE_CAPACITY: usize = 1;

/// Also implemented by the router's DNS seam, so TUN hijacking and named
/// functional DNS routes share the framing and cancellation implementation.
#[async_trait]
pub(crate) trait DnsExchange: Send + Sync {
    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError>;
}

struct RuntimeExchange(Weak<RuntimeDns>);

#[async_trait]
impl DnsExchange for RuntimeExchange {
    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
        let dns = self.0.upgrade().ok_or(DispatchError::HostUnreachable)?;
        dns.exchange_retained(query)
            .await
            .map_err(|error| match error {
                RuntimeDnsError::RuleEvaluation(failure) => DispatchError::RuleEvaluation(failure),
                _ => DispatchError::HostUnreachable,
            })
    }
}

#[derive(Default)]
pub(crate) struct DnsOutbound {
    admission: Mutex<()>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl DnsOutbound {
    fn exchange(context: &EstablishContext) -> Result<Arc<dyn DnsExchange>, DispatchError> {
        if context.deadline() <= Instant::now() {
            return Err(DispatchError::TimedOut);
        }
        let dns = context
            .resolution()
            .runtime_dns()
            .filter(|dns| dns.is_enabled())
            .ok_or(DispatchError::HostUnreachable)?;
        Ok(Arc::new(RuntimeExchange(Arc::downgrade(&dns))))
    }
}

#[async_trait]
impl OutboundConnector for DnsOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let exchange = Self::exchange(context)?;
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        Ok(ConnectedStream {
            io: dns_tcp_stream(exchange, self.cancel.child_token(), Some(&self.tasks)),
            effective_peer: session.destination,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let exchange = Self::exchange(context)?;
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        let cancel = self.cancel.child_token();
        let (queries, receiver) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
        let (sender, responses) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
        let response_limit = usize::from(request.max_response_payload_size()).min(MAX_MESSAGE_SIZE);
        let worker = self
            .tasks
            .spawn(crate::resources::observation::task(dns_datagrams(
                exchange,
                receiver,
                sender,
                cancel.clone(),
                response_limit,
            )));
        Ok(crate::dispatch::bound_datagram(
            Box::new(DnsDatagram {
                queries,
                responses,
                cancel,
                worker: Some(worker),
                response_limit: response_limit as u16,
            }),
            request.budget(),
        ))
    }

    fn begin_shutdown(&self) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cancel.cancel();
        self.tasks.close();
    }

    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
    }
}

/// The stream owns its worker handle; an abandoned inbound cannot detach a DNS
/// exchange. The optional tracker additionally joins named-node work at Stop.
pub(crate) fn dns_tcp_stream(
    exchange: Arc<dyn DnsExchange>,
    cancel: CancellationToken,
    tasks: Option<&TaskTracker>,
) -> BoxStream {
    let (client, server) = tokio::io::duplex(TCP_DNS_DUPLEX_CAPACITY);
    let relay = crate::resources::observation::task(dns_tcp_relay(server, exchange, cancel));
    let relay = match tasks {
        Some(tasks) => tasks.spawn(relay),
        None => tokio::spawn(relay),
    };
    Box::new(DnsTcpStream {
        inner: client,
        relay,
    })
}

async fn dns_tcp_relay(
    mut server: DuplexStream,
    exchange: Arc<dyn DnsExchange>,
    cancel: CancellationToken,
) {
    let mut query = vec![0_u8; MAX_MESSAGE_SIZE];
    let mut length = [0_u8; 2];
    loop {
        let read = tokio::select! { biased;
            () = cancel.cancelled() => break,
            read = server.read_exact(&mut length) => read,
        };
        if read.is_err() {
            break;
        }
        let length = usize::from(u16::from_be_bytes(length));
        if !(1..=MAX_MESSAGE_SIZE).contains(&length) {
            break;
        }
        let read = tokio::select! { biased;
            () = cancel.cancelled() => break,
            read = server.read_exact(&mut query[..length]) => read,
        };
        if read.is_err() {
            break;
        }
        let response = tokio::select! { biased;
            () = cancel.cancelled() => break,
            response = exchange.exchange(&query[..length]) => response,
        };
        let Ok(response) = response else { break };
        if response.wire().is_empty() || response.wire().len() > MAX_MESSAGE_SIZE {
            break;
        }
        let write = async {
            server
                .write_all(&(response.wire().len() as u16).to_be_bytes())
                .await?;
            server.write_all(response.wire()).await
        };
        let written = tokio::select! { biased;
            () = cancel.cancelled() => break,
            written = write => written,
        };
        if written.is_err() {
            break;
        }
    }
    let _ = server.shutdown().await;
}

struct DnsTcpStream {
    inner: DuplexStream,
    relay: JoinHandle<()>,
}

impl AsyncRead for DnsTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for DnsTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Drop for DnsTcpStream {
    fn drop(&mut self) {
        self.relay.abort();
    }
}

struct DnsPacket {
    remote: Destination,
    response: DnsWireResponse,
}

impl DnsPacket {
    fn into_datagram(self) -> Datagram {
        Datagram {
            remote: self.remote,
            payload: Bytes::from(self.response.into_wire()),
            sniffed_domain: None,
        }
    }
}

async fn dns_datagrams(
    exchange: Arc<dyn DnsExchange>,
    mut queries: mpsc::Receiver<Datagram>,
    responses: mpsc::Sender<DnsPacket>,
    cancel: CancellationToken,
    response_limit: usize,
) {
    loop {
        let query = tokio::select! { biased;
            () = cancel.cancelled() => break,
            query = queries.recv() => match query { Some(query) => query, None => break },
        };
        let result = tokio::select! { biased;
            () = cancel.cancelled() => break,
            result = exchange.exchange(&query.payload) => result,
        };
        let Ok(response) = result else { continue };
        if response.wire().is_empty() || response.wire().len() > response_limit {
            continue;
        }
        let response = DnsPacket {
            remote: query.remote,
            response,
        };
        tokio::select! { biased;
            () = cancel.cancelled() => break,
            sent = responses.send(response) => if sent.is_err() { break },
        }
    }
}

struct DnsDatagram {
    queries: mpsc::Sender<Datagram>,
    responses: mpsc::Receiver<DnsPacket>,
    cancel: CancellationToken,
    worker: Option<JoinHandle<()>>,
    response_limit: u16,
}

#[async_trait]
impl DatagramTransport for DnsDatagram {
    fn supports_shared_destinations(&self) -> bool {
        true
    }

    fn payload_budget(&self, _peer: &Destination) -> DatagramBudget {
        DatagramBudget::new(MAX_MESSAGE_SIZE as u16, self.response_limit)
    }

    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        if packet.payload.len() > MAX_MESSAGE_SIZE {
            return Ok(());
        }
        match self.queries.try_send(packet) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(DispatchError::NotAllowed),
        }
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(DispatchError::NotAllowed),
            response = self.responses.recv() => response.map(DnsPacket::into_datagram).ok_or(DispatchError::NotAllowed),
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.cancel.cancel();
        self.responses.close();
        if let Some(worker) = self.worker.take() {
            let _ = worker.await;
        }
        Ok(())
    }
}

impl Drop for DnsDatagram {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
