//! Node-owned sing-mux adapter over any normal protocol connector.
use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};
use crate::{
    config::SingMuxConfig,
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    session::{Destination, StreamSession},
    transport::sing_mux::{Pool, datagram::DatagramIo},
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tokio_util::sync::CancellationToken;

pub struct SingMuxConnector {
    inner: Arc<dyn OutboundConnector>,
    pool: Pool,
    cancellation: CancellationToken,
}
impl std::fmt::Debug for SingMuxConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingMuxConnector").finish_non_exhaustive()
    }
}
impl SingMuxConnector {
    /// Wrap an inner node with normalized, enabled smux options.
    pub fn new(inner: Arc<dyn OutboundConnector>, options: SingMuxConfig) -> Self {
        Self {
            inner,
            pool: Pool::new(options),
            cancellation: CancellationToken::new(),
        }
    }
    async fn connect(
        &self,
        mut session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<BoxStream> {
        session.destination = Destination::domain("sp.mux.sing-box.arpa", 444)?;
        session.sniffed_domain = None;
        self.inner
            .connect_stream(session, context)
            .await
            .map(|connected| connected.io)
            .map_err(io::Error::other)
    }
}
#[async_trait]
impl OutboundConnector for SingMuxConnector {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let effective_peer = session.destination.clone();
        let io = self
            .pool
            .open(&effective_peer, false, context.deadline(), || {
                self.connect(session, context)
            })
            .await?;
        Ok(ConnectedStream { io, effective_peer })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        tokio::select! { biased;
            ()=self.cancellation.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                if self.pool.only_tcp() { return self.inner.open_datagram(request, context).await; }
                let target = Destination::domain("sp.mux.sing-box.arpa", 444)?;
                let session = StreamSession { metadata:request.session.metadata.clone(), inbound:request.session.inbound, source:request.session.source, destination:target.clone(), sniffed_domain:None };
                let io=self.pool.open(&target, true, context.deadline(), || self.connect(session, context)).await?;
                Ok(crate::dispatch::bound_datagram(Box::new(DatagramIo::new(io,request.budget(),context.resolution(),context.deadline(),self.cancellation.clone())),request.budget()))
            }=>result,
        }
    }
    fn begin_shutdown(&self) {
        self.cancellation.cancel();
        self.pool.begin_stop();
        self.inner.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.pool.stop().await;
        self.inner.shutdown().await;
    }
}
impl Drop for SingMuxConnector {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dispatch::{DatagramBudget, DatagramTransport},
        resources::observation::{ResourceKind, ResourceProbe},
        session::{DatagramSession, InboundKind},
    };
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::{sync::Notify, time::Instant};

    struct MuxPeer {
        calls: Mutex<Vec<(StreamSession, Instant)>>,
        tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
        probe: ResourceProbe,
    }
    #[async_trait]
    impl OutboundConnector for MuxPeer {
        async fn connect_stream(
            &self,
            session: StreamSession,
            context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            self.calls
                .lock()
                .unwrap()
                .push((session.clone(), context.deadline()));
            let (raw, mut peer) = tokio::io::duplex(65536);
            self.tasks.lock().unwrap().push(tokio::spawn(async move {
                let mut handshake = [0; 2];
                peer.read_exact(&mut handshake).await.unwrap();
                assert_eq!(handshake, [0, 2]);
                let mut connection = h2::server::handshake(peer).await.unwrap();
                let mut streams = Vec::new();
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    assert_eq!(request.method(), "CONNECT");
                    let mut output = reply.send_response(http::Response::new(()), false).unwrap();
                    output
                        .send_data(bytes::Bytes::from_static(b"\x00x"), false)
                        .unwrap();
                    streams.push((request, output));
                }
            }));
            Ok(ConnectedStream {
                io: Box::new(raw),
                effective_peer: session.destination,
            })
        }
        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            panic!("mux UDP must use inner TCP rather than native UDP");
        }
        async fn shutdown(&self) {
            // The wrapper must join its driver before releasing the supplied IO owner.
            assert_eq!(self.probe.snapshot().current(ResourceKind::Task), 0);
            let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
            for task in tasks {
                task.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn shared_wrapper_preserves_logical_peer_and_joins_mux_before_inner() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let inner = Arc::new(MuxPeer {
                    calls: Mutex::default(),
                    tasks: Mutex::default(),
                    probe: probe.clone(),
                });
                let node = SingMuxConnector::new(
                    inner.clone(),
                    SingMuxConfig {
                        enabled: true,
                        max_connections: 1,
                        ..Default::default()
                    },
                );
                let session = StreamSession {
                    metadata: crate::session::InboundMetadata {
                        local_port: 1080,
                        user: Some(Arc::from("alice")),
                    },
                    inbound: InboundKind::Socks5,
                    source: "127.0.0.1:1080".parse().unwrap(),
                    destination: Destination::domain("business.invalid", 443).unwrap(),
                    sniffed_domain: Some("sniffed.invalid".to_owned()),
                };
                let context = EstablishContext::default();
                let mut first = node
                    .connect_stream(session.clone(), &context)
                    .await
                    .unwrap();
                let mut sibling = node
                    .connect_stream(session.clone(), &context)
                    .await
                    .unwrap();
                assert_eq!(first.effective_peer, session.destination);
                assert_eq!(first.io.read_u8().await.unwrap(), b'x');
                assert_eq!(sibling.io.read_u8().await.unwrap(), b'x');
                let calls = inner.calls.lock().unwrap().clone();
                assert_eq!(calls.len(), 1);
                let physical = &calls[0].0;
                assert_eq!(physical.destination.authority(), "sp.mux.sing-box.arpa:444");
                assert_eq!(physical.inbound, session.inbound);
                assert_eq!(physical.source, session.source);
                assert_eq!(physical.metadata, session.metadata);
                assert!(physical.sniffed_domain.is_none());
                assert_eq!(calls[0].1, context.deadline());
                assert_eq!(probe.snapshot().current(ResourceKind::Pool), 1);
                assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
                first.io.shutdown().await.unwrap();
                node.shutdown().await;
                drop((first, sibling, node));
                assert!(probe.snapshot().is_idle());
            })
            .await;
    }

    #[derive(Default)]
    struct PendingUdp {
        request: Mutex<Option<(DatagramRequest, Instant)>>,
        entered: Notify,
        stopped: Mutex<Vec<&'static str>>,
    }
    #[async_trait]
    impl OutboundConnector for PendingUdp {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            panic!("only-tcp must not establish a mux TCP stream for UDP");
        }
        async fn open_datagram(
            &self,
            request: DatagramRequest,
            context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            *self.request.lock().unwrap() = Some((request, context.deadline()));
            self.entered.notify_one();
            std::future::pending().await
        }
        fn begin_shutdown(&self) {
            self.stopped.lock().unwrap().push("begin");
        }
        async fn shutdown(&self) {
            self.stopped.lock().unwrap().push("joined");
        }
    }

    #[tokio::test]
    async fn only_tcp_delegates_original_udp_metadata_budget_and_cancels_pending_setup() {
        let inner = Arc::new(PendingUdp::default());
        let node = SingMuxConnector::new(
            inner.clone(),
            SingMuxConfig {
                enabled: true,
                only_tcp: true,
                ..Default::default()
            },
        );
        let request = DatagramRequest::new(DatagramSession::new(
            InboundKind::Socks5,
            "127.0.0.1:10234".parse().unwrap(),
        ))
        .with_budget(DatagramBudget::new(913, 1714));
        let context = EstablishContext::default();
        let open = node.open_datagram(request.clone(), &context);
        tokio::pin!(open);
        tokio::select! {
            _ = inner.entered.notified() => {},
            _ = &mut open => panic!("inner setup should remain pending"),
        }
        let recorded = inner.request.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.0.session, request.session);
        assert_eq!(recorded.0.budget(), request.budget());
        assert_eq!(recorded.1, context.deadline());
        node.begin_shutdown();
        assert!(matches!(open.await, Err(DispatchError::NotAllowed)));
        node.shutdown().await;
        assert_eq!(*inner.stopped.lock().unwrap(), ["begin", "begin", "joined"]);
        assert!(matches!(
            node.open_datagram(request, &context).await,
            Err(DispatchError::NotAllowed)
        ));
    }
}
