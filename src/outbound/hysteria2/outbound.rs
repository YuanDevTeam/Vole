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
    sync::{Mutex as AsyncMutex, oneshot},
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
    current: Box<[AsyncMutex<Option<Arc<Session>>>]>,
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
            if let Some(session) = slot.lock().await.as_ref() {
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
        // Explicit bandwidth modes spread UDP receive/forward work across a
        // small fixed pool. A one-byte receive declaration cannot be divided.
        let count = if (config.up > 0 || config.down > 0) && config.down != 1 {
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
                if let Some(session) = current.as_ref().filter(|session|
                    !session.cancel.is_cancelled() && session.connection.close_reason().is_none()) {
                    return Ok(session.clone());
                }
                current.take();
                let (ready, reply) = oneshot::channel();
                let context = if self.config.handshake_timeout.is_zero() { context.clone() } else {
                    context.clone().capped_by(tokio::time::Instant::now().checked_add(self.config.handshake_timeout).ok_or(DispatchError::TimedOut)?)
                };
                let cancel = self.cancel.child_token();
                let guard = cancel.clone().drop_guard();
                {
                    let _admission = self.admission.lock().unwrap();
                    if self.cancel.is_cancelled() { return Err(DispatchError::NotAllowed); }
                    let config = self.config.clone();
                    let upstream = self.upstream.clone();
                    let server = self.server.clone();
                    let tls = self.tls.clone();
                    let realm_tls=self.realm_tls.clone();
                    let context = context.clone();
                    let bandwidth = Arc::new(super::bandwidth::Bandwidth::with_pacer(self.pacer.clone()));
                    let count = self.current.len() as u64;
                    let receive_rate = self.config.down / count + u64::from((index as u64) < self.config.down % count);
                    let task = observation::track(ResourceKind::Task);
                    self.tasks.spawn(observation::bind(async move {
                        let _task = task;
                        drive(config, upstream, server, tls, realm_tls, datagram, context, cancel, ready, bandwidth, receive_rate, count as usize).await;
                    }));
                }
                let session = reply.await.map_err(|_| DispatchError::ConnectionRefused)??;
                guard.disarm();
                *current = Some(session.clone());
                Ok(session)
            }) => result,
        }
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
    ready: oneshot::Sender<Result<Arc<Session>, DispatchError>>,
    bandwidth: Arc<super::bandwidth::Bandwidth>,
    receive_rate: u64,
    session_count: usize,
) {
    let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
    let mut ready = Some(ready);
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
            realm_tls.as_ref(),
            &mut realm_pending,
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
            .send_window(crate::limits::HY2_SEND_WINDOW as u64)
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
        ready
            .take()
            .unwrap()
            .send(Ok(session))
            .map_err(|_| DispatchError::ConnectionRefused)?;
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
    if let Some(ready) = ready {
        let _ = ready.send(Err(result
            .err()
            .unwrap_or(DispatchError::ConnectionRefused)));
    }
    if let Some(endpoint) = endpoint {
        endpoint.close(0_u8.into(), b"");
        let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, endpoint.wait_idle()).await;
    }
    runtime.stop().await;
    realm_pending.stop().await;
    if let Some(mut paths) = paths {
        paths.stop().await;
    }
}

fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("Hysteria2 QUIC exchange failed")
}
