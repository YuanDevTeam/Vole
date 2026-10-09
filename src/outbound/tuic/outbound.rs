use super::{
    activity::{Activity, Lease},
    failure,
    stream::Stream,
    wire,
};
use crate::{
    config::{TuicCongestion, TuicOutboundConfig},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        owned_stream::OwnedStream, server_destination,
    },
    resources::observation::{self, ResourceKind},
    security::{SecurityContext, StandardTlsClient, TlsClientOptions, TlsVersions},
    session::{DatagramSession, Destination, StreamSession},
    transport::quic::{self, OwnedRuntime},
};
use async_trait::async_trait;
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex as AsyncMutex, oneshot},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub struct TuicOutbound {
    config: Arc<TuicOutboundConfig>,
    server: Destination,
    upstream: UpstreamPath,
    tls: Arc<rustls::ClientConfig>,
    current: AsyncMutex<Option<Arc<Session>>>,
    cancel: CancellationToken,
    admission: Mutex<()>,
    tasks: TaskTracker,
}

struct Session {
    connection: quinn::Connection,
    cancel: CancellationToken,
    datagrams: Arc<super::datagram::Registry>,
    runtime: Arc<OwnedRuntime>,
    activity: Arc<Activity>,
}

impl std::fmt::Debug for TuicOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicOutbound").finish_non_exhaustive()
    }
}

impl TuicOutbound {
    /// Remaining actual Quinn datagram buffer, for bounded-backpressure checks.
    #[cfg(feature = "interop-test")]
    pub async fn datagram_buffer_space(&self) -> Option<usize> {
        self.current
            .lock()
            .await
            .as_ref()
            .map(|s| s.connection.datagram_send_buffer_space())
    }

    /// Actual Quinn controller identity for acceptance; no peer or credential data.
    #[cfg(feature = "interop-test")]
    pub async fn congestion_observation(&self) -> Option<TuicCongestion> {
        let current = self.current.lock().await;
        let controller = current.as_ref()?.connection.congestion_state().into_any();
        if controller.is::<quinn::congestion::Cubic>() {
            Some(TuicCongestion::Cubic)
        } else if controller.is::<quinn::congestion::NewReno>() {
            Some(TuicCongestion::NewReno)
        } else if controller.is::<quinn::congestion::Bbr>() {
            Some(TuicCongestion::Bbr)
        } else {
            None
        }
    }

    pub fn new_with_path(config: &TuicOutboundConfig, upstream: UpstreamPath) -> io::Result<Self> {
        Self::with_shared_security(config, upstream, &SecurityContext::new(), 64 * 1024)
    }

    pub(crate) fn with_shared_security(
        config: &TuicOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        config.validate().map_err(failure)?;
        let tls = StandardTlsClient::with_options(
            security,
            &config.tls.server_name,
            TlsClientOptions {
                versions: TlsVersions::Tls13,
                alpn: config.tls.alpn.clone(),
                certificate: config.tls.certificate.clone(),
                ..Default::default()
            },
            0,
            buffer_limit,
        )?
        .quic_config()?
        .0;
        Ok(Self {
            config: Arc::new(config.clone()),
            server: server_destination(&config.address, config.port)?,
            upstream,
            tls,
            current: AsyncMutex::new(None),
            cancel: CancellationToken::new(),
            admission: Mutex::new(()),
            tasks: TaskTracker::new(),
        })
    }

    async fn session(
        &self,
        datagram: DatagramSession,
        context: &EstablishContext,
    ) -> Result<(Arc<Session>, Lease), DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let _waiter = observation::track(ResourceKind::Waiter);
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(DispatchError::NotAllowed),
            result = context.run("TUIC session", async {
                let mut current = self.current.lock().await;
                if let Some(session) = current.as_ref().filter(|s| !s.cancel.is_cancelled() && s.connection.close_reason().is_none() && !s.datagrams.exhausted()) {
                    return Ok((session.clone(),session.activity.acquire()));
                }
                if let Some(previous)=current.take() { previous.activity.retire(); }
                let cancel = self.cancel.child_token();
                let guard = cancel.clone().drop_guard();
                let (ready, reply) = oneshot::channel();
                {
                    let _admission = self.admission.lock().unwrap();
                    if self.cancel.is_cancelled() { return Err(DispatchError::NotAllowed); }
                    let config = self.config.clone();
                    let upstream = self.upstream.clone();
                    let server = self.server.clone();
                    let tls = self.tls.clone();
                    let context = context.clone();
                    let task = observation::track(ResourceKind::Task);
                    self.tasks.spawn(observation::bind(async move {
                        let _task = task;
                        drive(config, upstream, server, tls, datagram, context, cancel, ready).await;
                    }));
                }
                let session = reply.await.map_err(|_|DispatchError::ConnectionRefused)??;
                guard.disarm();
                *current = Some(session.clone());
                let lease=session.activity.acquire();
                Ok((session,lease))
            }) => result,
        }
    }
}

#[async_trait]
impl OutboundConnector for TuicOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let header = wire::connect(&session.destination)?;
        let (shared, lease) = self
            .session(
                DatagramSession::new(session.inbound, session.source),
                context,
            )
            .await?;
        tokio::select! { biased;
            () = shared.cancel.cancelled() => Err(DispatchError::ConnectionRefused),
            result = context.run_io("TUIC Connect", async {
                let pair = shared.connection.open_bi().await.map_err(failure)?;
                let mut stream = Stream::new(pair,lease,shared.runtime.clone());
                stream.write_all(&header).await?;
                stream.flush().await?;
                Ok(ConnectedStream { io: Box::new(OwnedStream::new(Box::new(stream), shared.cancel.child_token())), effective_peer:session.destination })
            }) => result,
        }
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        loop {
            let (shared, lease) = self.session(request.session.clone(), context).await?;
            if let Some(transport) = shared.datagrams.open(
                shared.connection.clone(),
                shared.cancel.clone(),
                shared.runtime.clone(),
                request.budget(),
                lease,
            )? {
                return Ok(transport);
            }
            // Another concurrent admission consumed the last ID. The next
            // lookup retires this session under the same original deadline.
        }
    }

    fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.tasks.close();
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
        self.current.lock().await.take();
    }
}
impl Drop for TuicOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    config: Arc<TuicOutboundConfig>,
    upstream: UpstreamPath,
    server: Destination,
    tls: Arc<rustls::ClientConfig>,
    datagram: DatagramSession,
    context: EstablishContext,
    cancel: CancellationToken,
    ready: oneshot::Sender<Result<Arc<Session>, DispatchError>>,
) {
    let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
    let mut ready = Some(ready);
    let mut endpoint = None;
    let mut driver = None;
    let _pool = observation::track(ResourceKind::Pool);
    let datagrams = Arc::new(super::datagram::Registry::new(config.udp_mode));
    let activity = Arc::new(Activity::default());
    let operation = async {
        let handshake = observation::track(ResourceKind::Handshake);
        let destination = upstream.datagram_server(&server, &context).await?;
        let peer = context.resolve_ip(&destination).await?;
        let budget = DatagramBudget::new(
            crate::limits::TUIC_QUIC_PAYLOAD as u16,
            crate::limits::TUIC_QUIC_PAYLOAD as u16,
        );
        let raw = upstream
            .open_datagram(DatagramRequest::new(datagram).with_budget(budget), &context)
            .await?;
        let (socket, owned) = quic::attach(raw, peer, budget)?;
        driver = Some(owned);
        let mtu = socket.budget().quic_payload_limit()?;
        let mut limits = quinn::TransportConfig::default();
        limits
            .initial_mtu(mtu)
            .min_mtu(mtu)
            .mtu_discovery_config(None)
            .max_concurrent_bidi_streams(0_u8.into())
            .max_concurrent_uni_streams((crate::limits::TUIC_UNI_STREAMS as u32).into())
            .stream_receive_window((crate::limits::TUIC_STREAM_WINDOW as u32).into())
            .receive_window((crate::limits::TUIC_CONNECTION_WINDOW as u32).into())
            .send_window(crate::limits::TUIC_CONNECTION_WINDOW as u64)
            .datagram_receive_buffer_size(Some(crate::limits::TUIC_DATAGRAM_BUFFER))
            .datagram_send_buffer_size(crate::limits::TUIC_DATAGRAM_BUFFER)
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(failure)?))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .congestion_controller_factory(match config.congestion {
                TuicCongestion::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
                TuicCongestion::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
                TuicCongestion::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            });
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(failure)?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(Arc::new(limits));
        let mut options = quinn::EndpointConfig::default();
        options.max_udp_payload_size(mtu).map_err(failure)?;
        let mut ep =
            quinn::Endpoint::new_with_abstract_socket(options, None, socket, runtime.clone())?;
        ep.set_default_client_config(client);
        endpoint = Some(ep);
        let connection = endpoint
            .as_ref()
            .unwrap()
            .connect(peer, &config.tls.server_name)
            .map_err(failure)?
            .await
            .map_err(failure)?;
        let alpn = connection
            .handshake_data()
            .and_then(|v| v.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|v| v.protocol);
        if !alpn.is_some_and(|p| config.tls.alpn.contains(&p))
            || connection.max_datagram_size().is_none()
        {
            return Err(DispatchError::NotAllowed);
        }
        // Export from this established connection; no provider fork or token cache.
        let mut auth = [0_u8; 50];
        auth[..2].copy_from_slice(&[5, 0]);
        auth[2..18].copy_from_slice(config.uuid.as_bytes());
        connection
            .export_keying_material(
                &mut auth[18..],
                config.uuid.as_bytes(),
                config.password.as_bytes(),
            )
            .map_err(failure)?;
        let mut send = connection.open_uni().await.map_err(failure)?;
        AsyncWriteExt::write_all(&mut send, &auth)
            .await
            .map_err(failure)?;
        send.finish().map_err(failure)?;
        auth.fill(0);
        drop(handshake);
        let session = Arc::new(Session {
            connection: connection.clone(),
            cancel: cancel.clone(),
            datagrams: datagrams.clone(),
            runtime: runtime.clone(),
            activity: activity.clone(),
        });
        ready
            .take()
            .unwrap()
            .send(Ok(session))
            .map_err(|_| DispatchError::ConnectionRefused)?;
        let mut beat = tokio::time::interval(Duration::from_secs(10));
        beat.tick().await;
        tokio::select! {
            _=connection.closed()=>{},
            ()=activity.retired_and_idle()=>{},
            result=super::datagram::receive(&connection,&datagrams)=>{ result?; },
            result=async { loop { beat.tick().await; connection.send_datagram(bytes::Bytes::from_static(&[5,4])).map_err(failure)?; } #[allow(unreachable_code)] Ok::<_,io::Error>(()) }=>{ result?; },
        }
        Ok::<_, DispatchError>(())
    };
    let result = tokio::select! { biased;
        () = cancel.cancelled() => Err(DispatchError::NotAllowed),
        result = operation => result,
    };
    cancel.cancel();
    datagrams.close();
    if let Some(ready) = ready {
        let _ = ready.send(Err(result
            .err()
            .unwrap_or(DispatchError::ConnectionRefused)));
    }
    if let Some(ep) = endpoint {
        ep.close(0_u8.into(), b"");
        let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, ep.wait_idle()).await;
    }
    runtime.stop().await;
    if let Some(driver) = driver {
        let _ = driver.stop().await;
    }
}
