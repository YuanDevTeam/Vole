use crate::{
    config::Hysteria2OutboundConfig,
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        owned_stream::OwnedStream, server_destination,
    },
    resources::observation::{self, ResourceKind},
    security::{
        SecurityContext, StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsClientIdentity,
        TlsClientOptions, TlsVersions,
    },
    session::{DatagramSession, Destination, StreamSession},
    transport::quic::{self, OwnedRuntime},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex as AsyncMutex, watch},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// A node owns its authenticated sessions and all their drivers. Individual
/// streams never own a shared session's cancellation token.
pub struct Hysteria2Outbound {
    config: Arc<Hysteria2OutboundConfig>,
    server: Destination,
    upstream: UpstreamPath,
    tls: StandardTlsClient,
    realm_tls: Option<StandardTlsClient>,
    current: Box<[AsyncMutex<Option<Arc<Handshake>>>]>,
    pacer: Arc<super::bandwidth::Pacer>,
    cancel: CancellationToken,
    admission: Mutex<()>,
    tasks: TaskTracker,
}

struct Session {
    connection: quinn::Connection,
    cancel: CancellationToken,
    udp_enabled: bool,
    datagrams: Arc<super::datagram::Registry>,
    #[cfg(feature = "interop-test")]
    bandwidth: Arc<super::bandwidth::Bandwidth>,
}

#[derive(Clone)]
enum Ready {
    Pending,
    Open(Arc<Session>),
    Failed(Arc<DispatchError>),
}

/// A slot retains its offer even when every waiting call has gone away. The
/// driver owns publication and holds no Handshake Arc, so there is no cycle.
struct Handshake {
    cancel: CancellationToken,
    ready: watch::Receiver<Ready>,
}

impl Handshake {
    fn initializing(&self) -> bool {
        matches!(*self.ready.borrow(), Ready::Pending)
    }

    fn finished(&self) -> bool {
        matches!(*self.ready.borrow(), Ready::Failed(_))
    }

    async fn wait_ready(&self) -> Result<Arc<Session>, DispatchError> {
        let mut ready = self.ready.clone();
        loop {
            let state = ready.borrow_and_update().clone();
            match state {
                Ready::Open(session) => {
                    if session.cancel.is_cancelled() || session.connection.close_reason().is_some()
                    {
                        return Err(DispatchError::ConnectionRefused);
                    }
                    return Ok(session);
                }
                Ready::Failed(error) => return Err(copy_failure(&error)),
                Ready::Pending => {}
            }
            if ready.changed().await.is_err() {
                return Err(DispatchError::ConnectionRefused);
            }
        }
    }
}

struct CreationGuard<'a> {
    handshake: &'a Handshake,
    armed: bool,
}

impl Drop for CreationGuard<'_> {
    fn drop(&mut self) {
        if self.armed && self.handshake.initializing() {
            self.handshake.cancel.cancel();
        }
    }
}

fn copy_failure(error: &DispatchError) -> DispatchError {
    match error {
        DispatchError::NotAllowed => DispatchError::NotAllowed,
        DispatchError::RuleEvaluation(failure) => DispatchError::RuleEvaluation(*failure),
        DispatchError::NetworkUnreachable => DispatchError::NetworkUnreachable,
        DispatchError::HostUnreachable => DispatchError::HostUnreachable,
        DispatchError::ConnectionRefused => DispatchError::ConnectionRefused,
        DispatchError::TimedOut => DispatchError::TimedOut,
        DispatchError::Other(message) => DispatchError::Other(message.clone()),
    }
}

impl std::fmt::Debug for Hysteria2Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Outbound").finish_non_exhaustive()
    }
}

impl Hysteria2Outbound {
    /// Test-only controller/path evidence; no configuration or traffic addresses.
    #[cfg(feature = "interop-test")]
    pub async fn congestion_observation(&self) -> Option<(u64, quinn::ConnectionStats)> {
        for slot in &self.current {
            let slot = slot.lock().await;
            if let Some(handshake) = slot.as_ref()
                && let Ready::Open(session) = &*handshake.ready.borrow()
            {
                return Some((
                    session
                        .bandwidth
                        .rate
                        .load(std::sync::atomic::Ordering::Relaxed),
                    session.connection.stats(),
                ));
            }
        }
        None
    }
    pub fn new_with_path(
        config: &Hysteria2OutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        Self::with_shared_security(
            config,
            upstream,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            64 * 1024,
        )
    }

    pub(crate) fn with_shared_security(
        config: &Hysteria2OutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let tls = StandardTlsClient::with_options(
            security,
            &config.tls.server_name,
            TlsClientOptions {
                ech: config.tls.ech.clone(),
                versions: TlsVersions::Tls13,
                alpn: config.tls.alpn.clone(),
                certificate: config.tls.certificate.clone(),
                identity: config
                    .tls
                    .identity
                    .as_ref()
                    .map(|identity| {
                        TlsClientIdentity::from_pem(&identity.certificate, &identity.private_key)
                    })
                    .transpose()?,
                ..Default::default()
            },
            resumption_sessions,
            buffer_limit,
        )?;
        let realm_tls = config
            .realm
            .as_ref()
            .and_then(|options| options.tls.as_ref())
            .map(|policy| {
                StandardTlsClient::with_options(
                    security,
                    &policy.server_name,
                    TlsClientOptions {
                        versions: TlsVersions::Tls12And13,
                        alpn: policy.alpn.clone(),
                        certificate: policy.certificate.clone(),
                        identity: policy
                            .identity
                            .as_ref()
                            .map(|identity| {
                                TlsClientIdentity::from_pem(
                                    &identity.certificate,
                                    &identity.private_key,
                                )
                            })
                            .transpose()?,
                        ..Default::default()
                    },
                    0,
                    buffer_limit,
                )
            })
            .transpose()?;
        // Spread UDP receive/forward work across a small lazy pool. A one-byte
        // receive declaration cannot be divided.
        let count = if config.down != 1 {
            crate::limits::HY2_AUTH_SESSIONS
        } else {
            1
        };
        Ok(Self {
            config: Arc::new(config.clone()),
            server: server_destination(&config.address, config.port)?,
            upstream,
            tls,
            realm_tls,
            current: (0..count)
                .map(|_| AsyncMutex::new(None))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            pacer: Arc::new(super::bandwidth::Pacer::default()),
            cancel: CancellationToken::new(),
            admission: Mutex::new(()),
            tasks: TaskTracker::new(),
        })
    }

    async fn session(
        &self,
        datagram: DatagramSession,
        context: &EstablishContext,
    ) -> Result<Arc<Session>, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let _waiter = observation::track(ResourceKind::Waiter);
        let mut hash = DefaultHasher::new();
        datagram.source.hash(&mut hash);
        let index = (hash.finish() % self.current.len() as u64) as usize;
        tokio::select! {biased;
            () = self.cancel.cancelled() => Err(DispatchError::NotAllowed),
            result = context.run("Hysteria2 session", async {
                let mut current = self.current[index].lock().await;
                // A failed offer becomes replaceable only after its driver has
                // finished cleanup. Repeated calls cannot stack retiring tasks.
                let (handshake, created) = match current.as_ref().filter(|offer| !offer.finished()) {
                    Some(handshake) => (handshake.clone(), false),
                    None => {
                        let handshake = self.start_handshake(index, datagram, context)?;
                        *current = Some(handshake.clone());
                        (handshake, true)
                    }
                };
                let independent = !self.config.handshake_timeout.is_zero();
                // Default offers retain the creator's serialization and
                // cancellation semantics. Positive timeouts share a pending
                // offer without keeping its first waiter or the slot lock.
                if independent { drop(current); }
                let mut guard = CreationGuard {
                    handshake: &handshake,
                    armed: created && !independent,
                };
                let result = handshake.wait_ready().await;
                guard.armed = false;
                result
            }) => result,
        }
    }

    fn start_handshake(
        &self,
        index: usize,
        datagram: DatagramSession,
        context: &EstablishContext,
    ) -> Result<Arc<Handshake>, DispatchError> {
        let _admission = self.admission.lock().unwrap();
        if self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        let context = if self.config.handshake_timeout.is_zero() {
            context.clone()
        } else {
            context.hysteria2_handshake(self.config.handshake_timeout)?
        };
        let cancel = self.cancel.child_token();
        let (ready, receive) = watch::channel(Ready::Pending);
        let handshake = Arc::new(Handshake {
            cancel: cancel.clone(),
            ready: receive,
        });
        let config = self.config.clone();
        let upstream = self.upstream.clone();
        let server = self.server.clone();
        let tls = self.tls.clone();
        let realm_tls = self.realm_tls.clone();
        let bandwidth = Arc::new(super::bandwidth::Bandwidth::with_pacer(self.pacer.clone()));
        let count = self.current.len() as u64;
        let receive_rate =
            self.config.down / count + u64::from((index as u64) < self.config.down % count);
        let task = observation::track(ResourceKind::Task);
        self.tasks.spawn(observation::bind(async move {
            let _task = task;
            drive(
                config,
                upstream,
                server,
                tls,
                realm_tls,
                datagram,
                context,
                cancel,
                ready,
                bandwidth,
                receive_rate,
                count as usize,
            )
            .await;
        }));
        Ok(handshake)
    }
}

#[async_trait]
impl OutboundConnector for Hysteria2Outbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let request = super::wire::tcp_request(&session.destination)?;
        let shared = self
            .session(
                DatagramSession::new(session.inbound, session.source)
                    .with_metadata(session.metadata.clone()),
                context,
            )
            .await?;
        tokio::select! {biased;
            () = shared.cancel.cancelled() => Err(DispatchError::ConnectionRefused),
            result = context.run_io("Hysteria2 TCP request", async {
                let (mut send, recv) = shared.connection.open_bi().await.map_err(failure)?;
                tokio::io::AsyncWriteExt::write_all(&mut send, &request).await?;
                send.flush().await?;
                let stream = super::stream::TcpStream::new(recv, send);
                Ok(ConnectedStream {
                    io: Box::new(OwnedStream::new(Box::new(stream), shared.cancel.child_token())),
                    effective_peer: session.destination,
                })
            }) => result,
        }
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let session = self.session(request.session.clone(), context).await?;
        if !session.udp_enabled || session.connection.max_datagram_size().is_none() {
            return Err(DispatchError::NotAllowed);
        }
        session.datagrams.open(
            session.connection.clone(),
            session.cancel.clone(),
            self.config.udp_mtu,
            request.budget(),
        )
    }

    fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.tasks.close();
    }

    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
        for slot in &self.current {
            slot.lock().await.take();
        }
    }
}

impl Drop for Hysteria2Outbound {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    config: Arc<Hysteria2OutboundConfig>,
    upstream: UpstreamPath,
    server: Destination,
    tls: StandardTlsClient,
    realm_tls: Option<StandardTlsClient>,
    datagram: DatagramSession,
    context: EstablishContext,
    cancel: CancellationToken,
    ready: watch::Sender<Ready>,
    bandwidth: Arc<super::bandwidth::Bandwidth>,
    receive_rate: u64,
    session_count: usize,
) {
    let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
    let mut endpoint = None;
    let mut paths = None;
    let mut realm_pending = super::realm::Pending::default();
    let (datagrams, submissions) = super::datagram::Registry::new();
    let datagrams = Arc::new(datagrams);
    let _pool = observation::track(ResourceKind::Pool);
    let established = CancellationToken::new();
    let deadline = context.deadline();
    let operation = async {
        let _handshake = observation::track(ResourceKind::Handshake);
        let (tls, _) = tls
            .quic_config_with_context(&context)
            .await
            .map_err(failure)?;
        let (path, socket) = super::paths::Paths::open(
            config.clone(),
            upstream,
            &server,
            datagram,
            context,
            bandwidth.clone(),
            super::paths::RealmSetup {
                tls: realm_tls.as_ref(),
                pending: &mut realm_pending,
            },
        )
        .await?;
        let peer = path.peer;
        let mtu = path.mtu;
        paths = Some(path);
        let mut limits = quinn::TransportConfig::default();
        quic::configure_receive_windows(
            &mut limits,
            config.stream_window,
            config.connection_window,
            quic::RECEIVE_WINDOW_POLICY,
        )?;
        limits
            .initial_mtu(mtu)
            .min_mtu(mtu)
            .mtu_discovery_config(None)
            .max_concurrent_bidi_streams(0_u8.into())
            .max_concurrent_uni_streams((crate::limits::HY2_UNI_STREAMS as u32).into())
            .send_window((crate::limits::HY2_SEND_WINDOW / session_count) as u64)
            .datagram_receive_buffer_size(Some(
                crate::limits::HY2_DATAGRAM_RECEIVE_BUFFER / session_count,
            ))
            .datagram_send_buffer_size(crate::limits::HY2_DATAGRAM_SEND_BUFFER / session_count)
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(failure)?))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .congestion_controller_factory(bandwidth.clone());
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
        let (mut control, mut requests) = h3::client::builder()
            .max_field_section_size(crate::limits::HY2_AUTH_HEADERS as u64)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(failure)?;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header(
                "Hysteria-Auth",
                http::HeaderValue::from_bytes(config.password.as_bytes()).map_err(failure)?,
            )
            .header("Hysteria-CC-RX", receive_rate.to_string())
            .header("Hysteria-Padding", "padding")
            .body(())
            .map_err(failure)?;
        // The driver must be polled during auth and retained afterward. Do not
        // enable H3 DATAGRAM: Hysteria consumes raw QUIC DATAGRAM frames.
        let auth = async {
            let mut stream = requests.send_request(request).await.map_err(failure)?;
            stream.finish().await.map_err(failure)?;
            let response = stream.recv_response().await.map_err(failure)?;
            if response.status().as_u16() != 233 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let udp_enabled = response
                .headers()
                .get("Hysteria-UDP")
                .is_some_and(|value| value == "true");
            let server_rx = response
                .headers()
                .get("Hysteria-CC-RX")
                .ok_or(io::ErrorKind::InvalidData)?;
            let rate = super::bandwidth::negotiate(config.up, server_rx.as_bytes())?;
            bandwidth
                .rate
                .store(rate, std::sync::atomic::Ordering::Relaxed);
            Ok::<_, io::Error>(udp_enabled)
        };
        let udp_enabled = tokio::select! {
            _ = control.wait_idle() => return Err(DispatchError::ConnectionRefused),
            result = auth => result?,
        };
        drop(_handshake);
        let session = Arc::new(Session {
            connection: connection.clone(),
            cancel: cancel.clone(),
            udp_enabled,
            datagrams: datagrams.clone(),
            #[cfg(feature = "interop-test")]
            bandwidth: bandwidth.clone(),
        });
        if tokio::time::Instant::now() >= deadline {
            return Err(DispatchError::TimedOut);
        }
        established.cancel();
        ready.send_replace(Ready::Open(session));
        tokio::select! {
            _ = connection.closed() => {},
            _ = control.wait_idle() => {},
            _ = super::datagram::receive(&connection, &datagrams) => {},
            _ = super::datagram::transmit(&connection, &datagrams, submissions) => {},
            _ = paths.as_mut().unwrap().hopping(endpoint.as_ref().unwrap()) => {},
        }
        drop(requests);
        Ok::<_, DispatchError>(())
    };
    let result = tokio::select! {biased;
        () = cancel.cancelled() => Err(DispatchError::NotAllowed),
        () = async { tokio::select! { biased; () = established.cancelled() => std::future::pending::<()>().await, () = tokio::time::sleep_until(deadline) => {} } } => Err(DispatchError::TimedOut),
        result = operation => result,
    };
    cancel.cancel();
    datagrams.close();
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u8.into(), b"");
        let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, endpoint.wait_idle()).await;
    }
    runtime.stop().await;
    realm_pending.stop().await;
    if let Some(mut paths) = paths {
        paths.stop().await;
    }
    ready.send_replace(Ready::Failed(Arc::new(
        result.err().unwrap_or(DispatchError::ConnectionRefused),
    )));
}

fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("Hysteria2 QUIC exchange failed")
}

#[cfg(test)]
mod shared_handshake_memory_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{sync::Notify, time::Instant};

    #[derive(Default)]
    struct PendingUpstream {
        entered: Notify,
        fail: Notify,
        calls: AtomicUsize,
        active: AtomicUsize,
        deadline: Mutex<Option<Instant>>,
    }

    struct Active<'a>(&'a AtomicUsize);

    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl OutboundConnector for PendingUpstream {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            panic!("memory fixture does not create a stream")
        }

        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.active.fetch_add(1, Ordering::Relaxed);
            let _active = Active(&self.active);
            *self.deadline.lock().unwrap() = Some(context.deadline());
            self.entered.notify_one();
            // Stop before creating any socket, QUIC endpoint or peer. The
            // actual production owner/driver/cancellation path remains in use.
            self.fail.notified().await;
            Err(DispatchError::ConnectionRefused)
        }
    }

    fn outbound(seconds: u64, upstream: Arc<PendingUpstream>) -> Hysteria2Outbound {
        let config = crate::config::Config::parse_yaml(
            format!(
                "proxies: [{{name: synthetic, type: hysteria2, server: 192.0.2.10, port: 443, password: synthetic, handshake-timeout: {seconds}}}]"
            )
            .as_bytes(),
        )
        .unwrap();
        let crate::config::ProxyProtocol::Hysteria2(config) = &config.proxies[0].protocol else {
            panic!("Hysteria2 configuration")
        };
        Hysteria2Outbound::new_with_path(config, UpstreamPath::proxy(upstream)).unwrap()
    }

    fn datagram() -> DatagramSession {
        DatagramSession::new(
            crate::session::InboundKind::Tun,
            "192.0.2.1:1000".parse().unwrap(),
        )
    }

    async fn current(outbound: &Hysteria2Outbound) -> Arc<Handshake> {
        for slot in &outbound.current {
            if let Some(handshake) = slot.lock().await.as_ref() {
                return handshake.clone();
            }
        }
        panic!("an offer was admitted")
    }

    #[tokio::test(start_paused = true)]
    async fn positive_offer_survives_waiter_timeout_and_last_waiter_drop() {
        let upstream = Arc::new(PendingUpstream::default());
        let outbound = outbound(5, upstream.clone());
        let short = EstablishContext::with_timeout(Duration::from_millis(10));
        let long = EstablishContext::with_timeout(Duration::from_secs(10));
        let mut creator = Box::pin(outbound.session(datagram(), &short));
        assert!(futures_util::poll!(creator.as_mut()).is_pending());
        upstream.entered.notified().await;
        let handshake = current(&outbound).await;
        let weak = Arc::downgrade(&handshake);
        let mut waiter = Box::pin(outbound.session(datagram(), &long));
        assert!(futures_util::poll!(waiter.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(50)).await;
        assert!(matches!(creator.await, Err(DispatchError::TimedOut)));
        assert!(!handshake.cancel.is_cancelled());
        assert!(futures_util::poll!(waiter.as_mut()).is_pending());
        drop(waiter);
        assert!(!handshake.cancel.is_cancelled());
        assert!(handshake.initializing());
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
        assert_eq!(upstream.active.load(Ordering::Relaxed), 1);
        assert!(*upstream.deadline.lock().unwrap().as_ref().unwrap() > short.deadline());
        outbound.shutdown().await;
        assert!(handshake.finished());
        assert_eq!(upstream.active.load(Ordering::Relaxed), 0);
        assert!(outbound.tasks.is_empty());
        drop(handshake);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn default_offer_keeps_creator_cancellation_and_one_serialized_attempt() {
        let upstream = Arc::new(PendingUpstream::default());
        let outbound = outbound(0, upstream.clone());
        let context = EstablishContext::with_timeout(Duration::from_secs(5));
        let mut creator = Box::pin(outbound.session(datagram(), &context));
        assert!(futures_util::poll!(creator.as_mut()).is_pending());
        upstream.entered.notified().await;
        let mut waiter = Box::pin(outbound.session(datagram(), &context));
        assert!(futures_util::poll!(waiter.as_mut()).is_pending());
        drop(waiter);
        assert_eq!(upstream.active.load(Ordering::Relaxed), 1);
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
        assert_eq!(*upstream.deadline.lock().unwrap(), Some(context.deadline()));
        drop(creator);
        outbound.shutdown().await;
        assert_eq!(upstream.active.load(Ordering::Relaxed), 0);
        assert!(outbound.tasks.is_empty());
        for slot in &outbound.current {
            assert!(slot.lock().await.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_offer_finishes_before_one_replacement_and_stop_joins_it() {
        for deadline_failure in [false, true] {
            let upstream = Arc::new(PendingUpstream::default());
            let outbound = outbound(1, upstream.clone());
            let context = EstablishContext::with_timeout(Duration::from_secs(10));
            let mut first = Box::pin(outbound.session(datagram(), &context));
            assert!(futures_util::poll!(first.as_mut()).is_pending());
            upstream.entered.notified().await;
            let old = current(&outbound).await;
            if deadline_failure {
                tokio::time::advance(Duration::from_secs(1)).await;
                assert!(matches!(first.await, Err(DispatchError::TimedOut)));
            } else {
                upstream.fail.notify_one();
                assert!(matches!(first.await, Err(DispatchError::ConnectionRefused)));
            }
            assert!(old.finished());
            assert_eq!(upstream.active.load(Ordering::Relaxed), 0);
            let mut retry = Box::pin(outbound.session(datagram(), &context));
            assert!(futures_util::poll!(retry.as_mut()).is_pending());
            upstream.entered.notified().await;
            let next = current(&outbound).await;
            assert!(!Arc::ptr_eq(&old, &next));
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 2);
            assert_eq!(upstream.active.load(Ordering::Relaxed), 1);
            outbound.shutdown().await;
            assert!(matches!(retry.await, Err(DispatchError::NotAllowed)));
            assert!(next.finished());
            assert_eq!(upstream.active.load(Ordering::Relaxed), 0);
            assert!(outbound.tasks.is_empty());
            assert!(matches!(
                outbound.session(datagram(), &context).await,
                Err(DispatchError::NotAllowed)
            ));
        }
    }
}
