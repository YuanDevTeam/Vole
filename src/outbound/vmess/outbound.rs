use super::{
    BodyCipher, BodyOptions, ClientHandshake, Command, MAX_PACKET_BYTES, VmessDatagram,
    VmessIdentity, VmessStream,
};
use crate::{
    config::{VmessCipher, VmessOutboundConfig, VmessPacketEncoding, VmessTransport},
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        owned_stream::OwnedStream, server_destination,
    },
    resources::observation::{self, ResourceKind},
    security::{SecurityClient, SecurityContext, TLS_RESUMPTION_SESSION_BUDGET},
    session::{Datagram, Destination, StreamSession},
    transport::{GrpcPool, connect_websocket, http_obfs, legacy_h2},
};
use async_trait::async_trait;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::{io::AsyncWriteExt, time::Instant};
use tokio_util::{
    sync::{CancellationToken, WaitForCancellationFutureOwned},
    task::TaskTracker,
};

struct SessionOptions {
    identity: VmessIdentity,
    body: BodyOptions,
    transport: VmessTransport,
}

pub struct VmessOutbound {
    server: Destination,
    upstream: UpstreamPath,
    security: SecurityClient,
    options: Arc<SessionOptions>,
    encoding: VmessPacketEncoding,
    grpc_pool: Option<GrpcPool>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    driver_admission: Arc<Mutex<()>>,
}

impl std::fmt::Debug for VmessOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessOutbound").finish_non_exhaustive()
    }
}

impl VmessOutbound {
    pub fn new_with_path(config: &VmessOutboundConfig, upstream: UpstreamPath) -> io::Result<Self> {
        Self::with_shared_security(
            config,
            upstream,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            64 * 1024,
        )
    }
    pub(crate) fn with_shared_security(
        config: &VmessOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        sessions: usize,
        buffer: usize,
    ) -> io::Result<Self> {
        let cipher = match config.cipher {
            VmessCipher::Auto => BodyCipher::Auto,
            VmessCipher::Aes128Gcm => BodyCipher::Aes128Gcm,
            VmessCipher::Chacha20Poly1305 => BodyCipher::Chacha20Poly1305,
            VmessCipher::None => BodyCipher::None,
        };
        let security = SecurityClient::from_security_with_context(
            &config.security,
            security,
            sessions,
            buffer,
        )?;
        Ok(Self {
            server: server_destination(&config.address, config.port)?,
            upstream,
            security,
            options: Arc::new(SessionOptions {
                identity: VmessIdentity::new(config.id),
                body: BodyOptions::new(cipher, config.global_padding, config.authenticated_length)?,
                transport: config.transport.clone(),
            }),
            encoding: config.packet_encoding,
            grpc_pool: match &config.transport {
                VmessTransport::Grpc { options, .. } => Some(GrpcPool::new(options.clone())),
                _ => None,
            },
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
            driver_admission: Arc::new(Mutex::new(())),
        })
    }
    async fn connect_transport(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?
            .io;
        context
            .run_io(
                "VMess transport handshake",
                self.security.connect_with_context(raw, context),
            )
            .await
    }
    async fn prepare(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<PreparedStream, DispatchError> {
        if Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        tokio::select! { biased;
            ()=self.cancellation.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                let raw=if let VmessTransport::Grpc { uri, .. }=&self.options.transport {
                    self.grpc_pool.as_ref().expect("gRPC pool").open(uri,context.deadline(),||async {
                        self.connect_transport(session,context).await.map_err(io::Error::other)
                    }).await?
                } else { self.connect_transport(session,context).await? };
                let token=self.cancellation.child_token();
                Ok(PreparedStream { raw:Box::new(OwnedStream::new(raw,token.clone())),options:self.options.clone(),deadline:context.deadline(),tasks:self.tasks.clone(),token,driver_admission:self.driver_admission.clone() })
            }=>result,
        }
    }
}

struct PreparedStream {
    raw: BoxStream,
    options: Arc<SessionOptions>,
    deadline: Instant,
    tasks: TaskTracker,
    token: CancellationToken,
    driver_admission: Arc<Mutex<()>>,
}
impl PreparedStream {
    async fn finish(
        self,
        command: Command,
        target: &Destination,
    ) -> Result<VmessStream, DispatchError> {
        if Instant::now() >= self.deadline {
            return Err(DispatchError::TimedOut);
        }
        let handshake =
            ClientHandshake::new(&self.options.identity, command, target, self.options.body)?;
        let whole_close = matches!(
            self.options.transport,
            VmessTransport::Grpc { .. } | VmessTransport::Http { .. } | VmessTransport::H2 { .. }
        );
        let deadline = self.deadline;
        let result = tokio::time::timeout_at(deadline, async {
            let mut raw = self.raw;
            let mut sent = false;
            let mut driver = None;
            match &self.options.transport {
                VmessTransport::Tcp => {}
                VmessTransport::WebSocket { .. } => {
                    raw = connect_websocket(
                        raw,
                        &self
                            .options
                            .transport
                            .websocket_options()?
                            .expect("validated websocket"),
                        handshake.request(),
                        deadline,
                    )
                    .await?;
                    sent = true;
                }
                VmessTransport::Http { .. } => {
                    raw = http_obfs(
                        raw,
                        &self
                            .options
                            .transport
                            .http_options()?
                            .expect("validated http"),
                        handshake.request(),
                        deadline,
                    )
                    .await?;
                    sent = true;
                }
                // prepare already opened this logical gRPC stream. Authentication
                // is fresh here, without wrapping or dialing the transport again.
                VmessTransport::Grpc { .. } => {}
                VmessTransport::H2 { uris } => {
                    let uri = &uris[rand::random_range(0..uris.len())];
                    let connected = legacy_h2(raw, uri, deadline).await?;
                    raw = connected.0;
                    driver = Some(connected.1);
                }
            }
            if let Some(driver) = driver {
                let token = self.token.clone();
                let observation = observation::track(ResourceKind::Task);
                let task = observation::bind(async move {
                    let _observation = observation;
                    token.cancelled().await;
                    let _ = driver.stop().await;
                });
                let unregistered = {
                    let _admission = self
                        .driver_admission
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if self.token.is_cancelled() {
                        Some(task)
                    } else {
                        self.tasks.spawn(task);
                        None
                    }
                };
                if let Some(task) = unregistered {
                    task.await;
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
            }
            // Dropping setup after a partial header must also stop an H2 driver.
            let guard = self.token.clone().drop_guard();
            if !sent {
                raw.write_all(handshake.request()).await?;
                raw.flush().await?;
            }
            // Complete request submission uses the setup deadline. A peer can
            // send its response header with the first application reply.
            let stream = VmessStream::new(raw, handshake);
            guard.disarm();
            Ok::<_, io::Error>(if whole_close {
                stream.with_whole_close()
            } else {
                stream
            })
        })
        .await
        .map_err(|_| DispatchError::TimedOut)??;
        Ok(result)
    }
}

#[async_trait]
impl OutboundConnector for VmessOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let prepared = self.prepare(session, context).await?;
        let token = prepared.token.clone();
        let stream = prepared.finish(Command::Tcp, &effective_peer).await?;
        Ok(ConnectedStream {
            io: Box::new(OwnedStream::new(Box::new(stream), token)),
            effective_peer,
        })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: self.server.clone(),
            sniffed_domain: None,
        };
        // Select the physical upstream once now. Raw UDP learns its authenticated
        // target from the first send, under this same absolute setup deadline.
        let prepared = self.prepare(session, context).await?;
        let token = prepared.token.clone();
        let budget = request.budget().intersect(DatagramBudget::new(
            MAX_PACKET_BYTES as u16,
            MAX_PACKET_BYTES as u16,
        ));
        let (pending, inner) = if self.encoding == VmessPacketEncoding::Raw {
            (Some(prepared), None)
        } else {
            let (command, magic) = if self.encoding == VmessPacketEncoding::Xudp {
                (Command::Mux, "v1.mux.cool")
            } else {
                (Command::Udp, "sp.packet-addr.v2fly.arpa")
            };
            let stream = prepared
                .finish(command, &Destination::domain(magic, 443)?)
                .await?;
            let inner: Box<dyn DatagramTransport> = if self.encoding == VmessPacketEncoding::Xudp {
                Box::new(crate::xudp::XudpTransport::with_budget(
                    Box::new(stream),
                    [0; 8],
                    budget,
                ))
            } else {
                Box::new(VmessDatagram::packet_addr(
                    stream,
                    budget,
                    context.resolution(),
                ))
            };
            (None, Some(inner))
        };
        Ok(crate::dispatch::bound_datagram(
            Box::new(SessionDatagram::new(pending, inner, budget, token)),
            request.budget(),
        ))
    }
    fn begin_shutdown(&self) {
        let _admission = self
            .driver_admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cancellation.cancel();
        self.tasks.close();
        if let Some(pool) = &self.grpc_pool {
            pool.begin_shutdown();
        }
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.close();
        self.tasks.wait().await;
        if let Some(pool) = &self.grpc_pool {
            pool.shutdown().await;
        }
    }
}
impl Drop for VmessOutbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct SessionDatagram {
    pending: Option<PreparedStream>,
    inner: Option<Box<dyn DatagramTransport>>,
    budget: DatagramBudget,
    token: CancellationToken,
    read_cancel: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
    pending_reader: Option<Waker>,
}
impl SessionDatagram {
    fn new(
        pending: Option<PreparedStream>,
        inner: Option<Box<dyn DatagramTransport>>,
        budget: DatagramBudget,
        token: CancellationToken,
    ) -> Self {
        // Keep one read-only cancellation registration for the whole polled
        // session: OwnedStream's registration can be replaced by a writer waker.
        // Lazy raw must advertise this capability before installing its inner.
        let polled = pending.is_some()
            || inner
                .as_ref()
                .is_some_and(|inner| inner.supports_poll_receive());
        let read_cancel = polled.then(|| Box::pin(token.clone().cancelled_owned()));
        Self {
            pending,
            inner,
            budget,
            token,
            read_cancel,
            pending_reader: None,
        }
    }
}
impl Drop for SessionDatagram {
    fn drop(&mut self) {
        self.token.cancel();
    }
}
#[async_trait]
impl DatagramTransport for SessionDatagram {
    fn supports_poll_receive(&self) -> bool {
        self.read_cancel.is_some()
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        let cancelled = self.token.is_cancelled()
            || self
                .read_cancel
                .as_mut()
                .is_some_and(|cancelled| cancelled.as_mut().poll(context).is_ready());
        if cancelled {
            self.pending.take();
            self.inner.take();
            self.read_cancel.take();
            self.pending_reader.take();
            return Poll::Ready(Err(DispatchError::NotAllowed));
        }
        if self.pending.is_some() {
            if self
                .pending_reader
                .as_ref()
                .is_none_or(|reader| !reader.will_wake(context.waker()))
            {
                self.pending_reader = Some(context.waker().clone());
            }
            return Poll::Pending;
        }
        match self.inner.as_mut() {
            Some(inner) => inner.poll_receive(context, scratch),
            None => Poll::Ready(Err(DispatchError::NotAllowed)),
        }
    }

    fn supports_shared_destinations(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.supports_shared_destinations())
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.inner.as_ref().map_or(self.budget, |inner| {
            self.budget.intersect(inner.payload_budget(peer))
        })
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if datagram.payload.is_empty()
            || datagram.remote.port() == 0
            || datagram.payload.len()
                > usize::from(self.payload_budget(&datagram.remote).transmit())
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let result = tokio::select! {biased;
            ()=self.token.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                if let Some(prepared)=self.pending.take() {
                    let stream=prepared.finish(Command::Udp,&datagram.remote).await?;
                    self.inner=Some(Box::new(VmessDatagram::raw(stream,datagram.remote.clone(),self.budget)));
                }
                self.inner.as_mut().ok_or(DispatchError::NotAllowed)?.send(datagram).await
            }=>result,
        };
        // Wake a reader waiting for lazy raw setup, but retain the independent
        // read cancellation waiter across every later read/write handoff.
        if result.is_ok()
            && let Some(reader) = self.pending_reader.take()
        {
            reader.wake();
        }
        result
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.supports_poll_receive() {
            let mut scratch = Vec::new();
            return std::future::poll_fn(|context| self.poll_receive(context, &mut scratch)).await;
        }
        let pending = self.pending.is_some();
        let inner = &mut self.inner;
        tokio::select! {biased;
            ()=self.token.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                if pending { return std::future::pending().await; }
                inner.as_mut().ok_or(DispatchError::NotAllowed)?.receive().await
            }=>result,
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.token.cancel();
        self.pending.take();
        self.inner.take();
        self.read_cancel.take();
        if let Some(reader) = self.pending_reader.take() {
            reader.wake();
        }
        Ok(())
    }
}

#[cfg(test)]
mod polled_datagram_memory_tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::task::{ArcWake, waker};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, DuplexStream};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl ArcWake for WakeCount {
        fn wake_by_ref(owner: &Arc<Self>) {
            owner.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn prepared(capacity: usize) -> (PreparedStream, DuplexStream, CancellationToken) {
        let (raw, peer) = tokio::io::duplex(capacity);
        // Match the node -> physical session hierarchy; the routing flow's
        // cancellation is deliberately a different token in the test below.
        let node = CancellationToken::new();
        let token = node.child_token();
        let prepared = PreparedStream {
            raw: Box::new(OwnedStream::new(Box::new(raw), token.clone())),
            options: Arc::new(SessionOptions {
                identity: VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
                body: BodyOptions::new(BodyCipher::None, false, false).unwrap(),
                transport: VmessTransport::Tcp,
            }),
            deadline: Instant::now() + Duration::from_secs(10),
            tasks: TaskTracker::new(),
            token,
            driver_admission: Arc::new(Mutex::new(())),
        };
        (prepared, peer, node)
    }

    fn pending_raw(capacity: usize) -> (SessionDatagram, DuplexStream, CancellationToken) {
        let (prepared, peer, node) = prepared(capacity);
        let token = prepared.token.clone();
        (
            SessionDatagram::new(Some(prepared), None, DatagramBudget::new(128, 128), token),
            peer,
            node,
        )
    }

    async fn installed_packetaddr() -> (SessionDatagram, DuplexStream, CancellationToken) {
        let (prepared, peer, node) = prepared(4096);
        let token = prepared.token.clone();
        let budget = DatagramBudget::new(128, 128);
        let stream = prepared
            .finish(
                Command::Udp,
                &Destination::domain("sp.packet-addr.v2fly.arpa", 443).unwrap(),
            )
            .await
            .unwrap();
        let inner = VmessDatagram::packet_addr(
            stream,
            budget,
            crate::dns::resolution::ResolutionContext::default(),
        );
        (
            SessionDatagram::new(None, Some(Box::new(inner)), budget, token),
            peer,
            node,
        )
    }

    fn packet() -> Datagram {
        Datagram {
            remote: Destination::Ip("192.0.2.1:53".parse().unwrap()),
            payload: Bytes::from_static(b"one application datagram"),
            sniffed_domain: None,
        }
    }

    #[tokio::test]
    async fn vmess_polled_receive_keeps_reader_wake_after_write_and_node_cancellation() {
        for packetaddr in [false, true] {
            let (mut transport, mut peer, node) = if packetaddr {
                installed_packetaddr().await
            } else {
                pending_raw(4096)
            };
            let reader = Arc::new(WakeCount::default());
            let writer = Arc::new(WakeCount::default());
            let reader_wake = waker(reader.clone());
            let writer_wake = waker(writer.clone());
            let mut scratch = Vec::new();
            assert!(transport.supports_poll_receive());
            if !packetaddr {
                // A lazy raw association is polled before its authenticated
                // destination exists, and must wake its latest reader on setup.
                let stale = Arc::new(WakeCount::default());
                let stale_wake = waker(stale.clone());
                assert!(
                    transport
                        .poll_receive(&mut Context::from_waker(&stale_wake), &mut scratch,)
                        .is_pending()
                );
                assert!(
                    transport
                        .poll_receive(&mut Context::from_waker(&reader_wake), &mut scratch,)
                        .is_pending()
                );
                let count = reader.0.load(Ordering::Relaxed);
                transport.send(packet()).await.unwrap();
                assert!(
                    reader.0.load(Ordering::Relaxed) > count,
                    "first committed raw send must wake the latest reader"
                );
                assert_eq!(stale.0.load(Ordering::Relaxed), 0);
            }
            // ReadyQueue also listens to an independent flow/connection token.
            // Node cancellation must wake the read key without cancelling it.
            let flow = CancellationToken::new();
            let mut flow_cancelled = Box::pin(flow.clone().cancelled_owned());
            assert!(
                flow_cancelled
                    .as_mut()
                    .poll(&mut Context::from_waker(&reader_wake),)
                    .is_pending()
            );
            assert!(
                transport
                    .poll_receive(&mut Context::from_waker(&reader_wake), &mut scratch,)
                    .is_pending()
            );
            let read_count = reader.0.load(Ordering::Relaxed);
            // This is a subsequent normal send for raw, and a normal packetaddr
            // send after installation. Both replace OwnedStream's read waker.
            {
                let mut sending = Box::pin(transport.send(packet()));
                assert!(matches!(
                    sending
                        .as_mut()
                        .poll(&mut Context::from_waker(&writer_wake),),
                    Poll::Ready(Ok(()))
                ));
            }
            assert_eq!(reader.0.load(Ordering::Relaxed), read_count);
            let write_count = writer.0.load(Ordering::Relaxed);
            node.cancel();
            assert!(
                reader.0.load(Ordering::Relaxed) > read_count,
                "normal send must not steal the read key's node-cancel wake"
            );
            assert!(
                writer.0.load(Ordering::Relaxed) > write_count,
                "the lower OwnedStream waiter should hold the writer waker"
            );
            assert!(
                !flow.is_cancelled(),
                "flow cancellation must not rescue this wake"
            );
            assert!(
                flow_cancelled
                    .as_mut()
                    .poll(&mut Context::from_waker(&reader_wake),)
                    .is_pending()
            );
            assert!(matches!(
                transport.poll_receive(&mut Context::from_waker(&reader_wake), &mut scratch,),
                Poll::Ready(Err(_))
            ));
            let mut submitted = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut submitted))
                .await
                .unwrap()
                .unwrap();
            assert!(!submitted.is_empty());
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn vmess_raw_polled_receive_survives_cancelled_pending_or_partial_first_send() {
        for partial in [false, true] {
            let (mut transport, mut peer, node) = pending_raw(1);
            let owner = Arc::new(WakeCount::default());
            let wake = waker(owner.clone());
            let mut scratch = Vec::new();
            assert!(
                transport
                    .poll_receive(&mut Context::from_waker(&wake), &mut scratch,)
                    .is_pending()
            );
            if partial {
                let sending = transport.send(packet());
                tokio::pin!(sending);
                assert!(futures_util::poll!(sending.as_mut()).is_pending());
            } else {
                node.cancel();
            }
            assert!(
                owner.0.load(Ordering::Relaxed) > 0,
                "pending reader lost cancellation wake"
            );
            assert!(matches!(
                transport.poll_receive(&mut Context::from_waker(&wake), &mut scratch,),
                Poll::Ready(Err(_))
            ));
            assert!(
                transport.send(packet()).await.is_err(),
                "partial first request must not replay"
            );
            let mut submitted = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut submitted))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(submitted.len(), usize::from(partial));
            transport.close().await.unwrap();
        }
    }
}
