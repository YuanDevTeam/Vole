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
    tls: StandardTlsClient,
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

fn active_congestion(connection: &quinn::Connection) -> Option<TuicCongestion> {
    let controller = connection.congestion_state().into_any();
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

fn log_active_congestion(connection: &quinn::Connection) {
    // Fixed targets survive the CLI's restricted field renderer without
    // exposing peer, credential or traffic metadata.
    match active_congestion(connection) {
        Some(TuicCongestion::Cubic) => {
            tracing::debug!(target: "vole::outbound::tuic::congestion::cubic", "TUIC controller ready");
        }
        Some(TuicCongestion::NewReno) => {
            tracing::debug!(target: "vole::outbound::tuic::congestion::new_reno", "TUIC controller ready");
        }
        Some(TuicCongestion::Bbr) => {
            tracing::debug!(target: "vole::outbound::tuic::congestion::bbr", "TUIC controller ready");
        }
        None => {
            tracing::debug!(target: "vole::outbound::tuic::congestion::unknown", "TUIC controller ready");
        }
    }
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
        active_congestion(&current.as_ref()?.connection)
    }

    /// Actual native path state for memory acceptance; not configured defaults.
    #[cfg(feature = "interop-test")]
    pub async fn path_observation(&self) -> Option<quinn::PathStats> {
        let current = self.current.lock().await;
        Some(current.as_ref()?.connection.stats().path)
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
                identity: config
                    .tls
                    .identity
                    .as_ref()
                    .map(|identity| {
                        crate::security::TlsClientIdentity::from_config(identity, security)
                    })
                    .transpose()?,
                ..Default::default()
            },
            0,
            buffer_limit,
        )?;
        // Validate the QUIC policy now, but snapshot the current file identity
        // only when a new physical connection is constructed.
        tls.quic_config()?;
        Ok(Self {
            config: Arc::new(config.clone()),
            server: server_destination(
                config.ip.as_deref().unwrap_or(&config.address),
                config.port,
            )?,
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
        // The reference admits only counters strictly below its threshold.
        // A configured threshold of one is valid, but permits no logical owner.
        if self.config.max_open_streams == 0 {
            return Err(DispatchError::NotAllowed);
        }
        let _waiter = observation::track(ResourceKind::Waiter);
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(DispatchError::NotAllowed),
            result = context.run("TUIC session", async {
                let mut current = self.current.lock().await;
                if let Some(session) = current.as_ref().filter(|s| !s.cancel.is_cancelled() && s.connection.close_reason().is_none() && !s.datagrams.exhausted())
                    && let Some(lease) = session.activity.try_acquire(self.config.max_open_streams) { return Ok((session.clone(),lease)); }
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
        if self.config.udp_over_stream {
            let connected = self
                .connect_stream(
                    StreamSession {
                        metadata: request.session.metadata.clone(),
                        inbound: request.session.inbound,
                        source: request.session.source,
                        destination: crate::outbound::uot::magic_destination(),
                        sniffed_domain: None,
                    },
                    context,
                )
                .await?;
            let _admission = self.admission.lock().unwrap();
            if self.cancel.is_cancelled() {
                return Err(DispatchError::NotAllowed);
            }
            let (reader, writer) = tokio::io::split(connected.io);
            return Ok(crate::dispatch::bound_datagram(
                Box::new(
                    crate::outbound::uot::UotTransport::new(
                        reader,
                        writer,
                        request.max_response_payload_size(),
                        self.cancel.clone(),
                        &self.tasks,
                    )
                    .with_initial_deadline(context.deadline()),
                ),
                request.budget(),
            ));
        }
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
    tls: StandardTlsClient,
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
    let datagrams = Arc::new(super::datagram::Registry::with_limit(
        config.udp_mode,
        config.max_udp_relay_packet_size,
        quic::datagram_payload_limit(config.max_datagram_frame_size),
    ));
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
        let (socket, owned) = quic::attach_quinn(raw, peer, budget).await?;
        driver = Some(owned);
        let mtu = socket.budget().quic_payload_limit()?;
        let mut limits = quinn::TransportConfig::default();
        socket.configure_transport(&mut limits);
        quic::configure_receive_windows(
            &mut limits,
            config.stream_window,
            config.connection_window,
            quic::RECEIVE_WINDOW_POLICY,
        )?;
        let discovery = if config.disable_mtu_discovery {
            None
        } else {
            let mut discovery = quinn::MtuDiscoveryConfig::default();
            discovery.upper_bound(mtu);
            Some(discovery)
        };
        let initial_mtu = if discovery.is_some() { 1200 } else { mtu };
        limits
            .initial_mtu(initial_mtu)
            .min_mtu(1200)
            .mtu_discovery_config(discovery)
            // Business owner thresholds never flow into Quinn's eager maps.
            // The decoder already bounds concurrent remote uni streams to 32.
            .max_concurrent_bidi_streams(0_u8.into())
            .max_concurrent_uni_streams((crate::limits::TUIC_CONTROL_READERS as u32).into())
            .send_window(crate::limits::TUIC_SEND_WINDOW as u64)
            .datagram_receive_buffer_size(Some(crate::limits::TUIC_DATAGRAM_BUFFER))
            .datagram_send_buffer_size(crate::limits::TUIC_DATAGRAM_BUFFER)
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(failure)?))
            .keep_alive_interval(Some(config.heartbeat_interval))
            .congestion_controller_factory(match config.congestion {
                TuicCongestion::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
                TuicCongestion::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
                TuicCongestion::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            });
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            current_tls(&tls, config.disable_sni).map_err(failure)?,
        )
        .map_err(failure)?;
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
        log_active_congestion(&connection);
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
        let mut beat = tokio::time::interval(config.heartbeat_interval);
        beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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

fn current_tls(
    tls: &StandardTlsClient,
    disable_sni: bool,
) -> io::Result<Arc<rustls::ClientConfig>> {
    let (mut config, _) = tls.quic_config()?;
    // The verifier still receives Quinn's immutable server name.
    if disable_sni {
        Arc::make_mut(&mut config).enable_sni = false;
    }
    Ok(config)
}

#[cfg(test)]
mod p08_tests {
    use super::*;
    #[tokio::test]
    async fn tuic_cold_connection_cannot_publish_an_early_quinn_handle_without_resumption() {
        struct Discard;
        #[async_trait]
        impl DatagramTransport for Discard {
            fn supports_shared_destinations(&self) -> bool {
                false
            }

            async fn send(&mut self, _: crate::session::Datagram) -> Result<(), DispatchError> {
                Ok(())
            }
            async fn receive(&mut self) -> Result<crate::session::Datagram, DispatchError> {
                std::future::pending().await
            }
        }
        let parsed = crate::config::Config::parse_yaml(
            br#"proxies: [{name: edge, type: tuic, server: peer.invalid, port: 443, uuid: 01234567-89ab-cdef-0123-456789abcdef}]"#,
        ).unwrap();
        let crate::config::ProxyProtocol::Tuic(config) = &parsed.proxies[0].protocol else {
            panic!("TUIC");
        };
        let node = TuicOutbound::new_with_path(
            config,
            UpstreamPath::LazyDirect {
                dialer: crate::dialer::Dialer::default(),
            },
        )
        .unwrap();
        // A request for early data alone cannot make a cold client connection
        // available. No sockets, system resolver, peers, or ticket cache exist.
        let mut tls = (*current_tls(&node.tls, config.disable_sni).unwrap()).clone();
        tls.enable_early_data = true;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let peer = "192.0.2.1:443".parse().unwrap();
        let (socket, driver) =
            quic::attach(Box::new(Discard), peer, DatagramBudget::new(1400, 1400)).unwrap();
        let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime.clone(),
        )
        .unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint.connect(peer, "peer.invalid").unwrap();
        assert!(
            connecting.into_0rtt().is_err(),
            "a cold client obtained an early handle"
        );
        endpoint.close(0_u8.into(), b"");
        runtime.stop().await;
        drop(endpoint);
        driver.stop().await.unwrap();
    }

    fn sni_extension(hello: &[u8]) -> bool {
        assert_eq!(hello[0], 1);
        let mut at = 4 + 2 + 32;
        at += 1 + usize::from(hello[at]);
        let ciphers = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 2 + ciphers;
        at += 1 + usize::from(hello[at]);
        let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 2;
        while at < end {
            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            if kind == 0 {
                return true;
            }
            at += 4 + len;
        }
        false
    }
    #[test]
    fn tuic_disable_sni_changes_real_quic_hello_without_changing_verification_policy() {
        for disable in [false, true] {
            let config=crate::config::Config::parse_yaml(serde_json::json!({"proxies":[{"name":"edge","type":"tuic","server":"peer.invalid","port":443,"uuid":"01234567-89ab-cdef-0123-456789abcdef","disable-sni":disable,"name-cert-verify":"identity.example","fingerprint":"12".repeat(32)}]}).to_string().as_bytes()).unwrap();
            let crate::config::ProxyProtocol::Tuic(config) = &config.proxies[0].protocol else {
                panic!("TUIC")
            };
            assert!(!config.tls.certificate.skip_cert_verify);
            assert_eq!(
                config.tls.certificate.verification_name.as_deref(),
                Some("identity.example")
            );
            assert_eq!(config.tls.certificate.fingerprint, Some([0x12; 32]));
            let node = TuicOutbound::new_with_path(
                config,
                UpstreamPath::LazyDirect {
                    dialer: crate::dialer::Dialer::default(),
                },
            )
            .unwrap();
            let mut connection = rustls::quic::ClientConnection::new(
                current_tls(&node.tls, config.disable_sni).unwrap(),
                rustls::quic::Version::V1,
                rustls::pki_types::ServerName::try_from(config.tls.server_name.clone()).unwrap(),
                Vec::new(),
            )
            .unwrap();
            let mut hello = Vec::new();
            connection.write_hs(&mut hello);
            assert_eq!(sni_extension(&hello), !disable);
        }
    }
}
