use std::{io, sync::Arc};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt as _;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    config::{
        StreamTransport, VlessOutboundConfig, VlessPacketEncoding, VlessTransport,
        XHttpMode as ConfigXHttpMode,
    },
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    security::{SecurityClient, SecurityContext, TLS_RESUMPTION_SESSION_BUDGET},
    session::{DatagramSession, StreamSession},
    transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode},
    xudp::XudpTransport,
};

const DEFAULT_VLESS_TLS_BUFFER_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct VlessResourceLimits {
    tls_buffer_limit: usize,
    xhttp_send_buffer_size: usize,
    xhttp_upload_chunk_size: usize,
}

impl VlessResourceLimits {
    pub(crate) const fn new(
        tls_buffer_limit: usize,
        xhttp_send_buffer_size: usize,
        xhttp_upload_chunk_size: usize,
    ) -> Self {
        Self {
            tls_buffer_limit,
            xhttp_send_buffer_size,
            xhttp_upload_chunk_size,
        }
    }
}

use super::{VlessCommand, VlessStream};
#[cfg(all(test, feature = "tls-fingerprint"))]
#[path = "fingerprint_leg_tests.rs"]
mod fingerprint_leg_tests;
#[cfg(all(test, feature = "outbound-socks5"))]
use crate::outbound::Socks5Outbound;
use crate::outbound::{
    ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    server_destination,
};

#[derive(Clone)]
struct VlessTransportLeg {
    server: crate::session::Destination,
    upstream: UpstreamPath,
    security: SecurityClient,
}

impl std::fmt::Debug for VlessTransportLeg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessTransportLeg")
            .field("server", &self.server)
            .field("upstream", &self.upstream)
            .field("security", &self.security)
            .finish()
    }
}

#[derive(Clone)]
struct VlessDownloadLeg {
    transport: VlessTransportLeg,
    xhttp: XHttpClient,
}

impl std::fmt::Debug for VlessDownloadLeg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessDownloadLeg")
            .field("transport", &self.transport)
            .field("xhttp", &self.xhttp)
            .finish()
    }
}

pub struct VlessOutbound {
    uuid: uuid::Uuid,
    encryption: Option<super::encryption::Client>,
    upload: VlessTransportLeg,
    xhttp: Option<XHttpClient>,
    download: Option<VlessDownloadLeg>,
    encoding: VlessPacketEncoding,
    transport: StreamTransport,
    stream_options: crate::config::VlessStreamOptions,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    grpc_pool: Option<crate::transport::GrpcPool>,
    vision: bool,
    vision_stats: Arc<crate::security::vision::SpliceStats>,
}

impl std::fmt::Debug for VlessOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessOutbound")
            .finish_non_exhaustive()
    }
}

impl VlessOutbound {
    /// Builds an outbound from configuration and an endpoint resolved during
    /// the host's prepare phase, before the VPN becomes active.
    pub fn new(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
    ) -> io::Result<Self> {
        Self::new_with_endpoints(config, endpoint, None, dialer)
    }

    /// Builds a directly connected node from endpoints resolved during the
    /// prepare phase. A distinct download server requires its own prepared
    /// endpoint; an identical server reuses the primary resolution.
    pub fn new_with_endpoints(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        download_endpoint: Option<ResolvedEndpoint>,
        dialer: Dialer,
    ) -> io::Result<Self> {
        let (upload_path, download_path) =
            Self::direct_paths(config, endpoint, download_endpoint, dialer)?;
        Self::new_with_paths(config, upload_path, download_path)
    }

    /// Builds a VLESS node on top of another configured outbound connector.
    /// Its server name remains a logical destination and is resolved by the
    /// upstream proxy.
    pub fn new_with_upstream(
        config: &VlessOutboundConfig,
        upstream: Arc<dyn OutboundConnector>,
    ) -> io::Result<Self> {
        let upload_path = UpstreamPath::proxy(upstream.clone());
        let download_path = config.download().map(|_| UpstreamPath::proxy(upstream));
        Self::new_with_paths(config, upload_path, download_path)
    }

    pub fn new_with_path(config: &VlessOutboundConfig, upstream: UpstreamPath) -> io::Result<Self> {
        let download_path = Self::download_path_from_primary(config, &upstream)?;
        Self::new_with_paths(config, upstream, download_path)
    }

    pub fn new_with_paths(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
    ) -> io::Result<Self> {
        let security_context = SecurityContext::new();
        let standard_tls_count = usize::from(matches!(
            &config.security,
            crate::config::SecurityConfig::Tls(_)
        )) + config.download().map_or(0, |download| {
            usize::from(matches!(
                &download.security,
                crate::config::SecurityConfig::Tls(_)
            ))
        });
        let resumption_sessions =
            if standard_tls_count == 0 || standard_tls_count > TLS_RESUMPTION_SESSION_BUDGET {
                0
            } else {
                TLS_RESUMPTION_SESSION_BUDGET / standard_tls_count
            };
        let upload_security = SecurityClient::from_proxy_with_context(
            config,
            &security_context,
            resumption_sessions,
            DEFAULT_VLESS_TLS_BUFFER_LIMIT,
        )?;
        let download_security = config
            .download()
            .map(|download| {
                SecurityClient::from_security_with_context(
                    &download.security,
                    &security_context,
                    resumption_sessions,
                    DEFAULT_VLESS_TLS_BUFFER_LIMIT,
                )
            })
            .transpose()?;
        Self::assemble(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
        )
    }

    /// Runtime graph constructor using instance-shared TLS material and an
    /// explicitly partitioned resumption-cache budget.
    pub(crate) fn new_with_shared_security(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        security_context: &SecurityContext,
        resumption_sessions: usize,
        limits: VlessResourceLimits,
    ) -> io::Result<Self> {
        let upload_security = SecurityClient::from_security_with_context(
            &config.security,
            security_context,
            resumption_sessions,
            limits.tls_buffer_limit,
        )?;
        let download_security = config
            .download()
            .map(|download| {
                SecurityClient::from_security_with_context(
                    &download.security,
                    security_context,
                    resumption_sessions,
                    limits.tls_buffer_limit,
                )
            })
            .transpose()?;
        Self::assemble_with_xhttp_limits(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
            limits.xhttp_send_buffer_size,
            limits.xhttp_upload_chunk_size,
        )
    }

    /// Builds a standard-TLS outbound with local interoperability-test roots.
    ///
    /// This constructor is absent from normal and release builds. It must only
    /// be enabled by the opt-in local Xray interoperability harness.
    #[cfg(feature = "interop-test")]
    #[doc(hidden)]
    pub fn new_with_test_tls_roots(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        Self::new_with_test_tls_roots_and_endpoints(config, endpoint, None, dialer, roots_der)
    }

    /// Test-only roots with independently prepared upload/download endpoints.
    #[cfg(feature = "interop-test")]
    #[doc(hidden)]
    pub fn new_with_test_tls_roots_and_endpoints(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        download_endpoint: Option<ResolvedEndpoint>,
        dialer: Dialer,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        let (upload_path, download_path) =
            Self::direct_paths(config, endpoint, download_endpoint, dialer)?;
        let roots = roots_der.into_iter().collect::<Vec<_>>();
        let upload_security = match &config.security {
            crate::config::SecurityConfig::Tls(_) => {
                SecurityClient::from_proxy_with_test_tls_roots(config, roots.clone())?
            }
            _ => SecurityClient::from_security(&config.security)?,
        };
        let download_security = config
            .download()
            .map(|download| match &download.security {
                crate::config::SecurityConfig::Tls(_) => {
                    SecurityClient::from_security_with_test_tls_roots(
                        &download.security,
                        roots.clone(),
                    )
                }
                crate::config::SecurityConfig::Reality(_)
                | crate::config::SecurityConfig::Jls(_)
                | crate::config::SecurityConfig::None => {
                    SecurityClient::from_security(&download.security)
                }
            })
            .transpose()?;
        Self::assemble(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
        )
    }

    fn validate_endpoint(
        address: &str,
        port: u16,
        endpoint: &ResolvedEndpoint,
        leg: &str,
    ) -> io::Result<()> {
        if endpoint.logical_host != address || endpoint.port != port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("resolved endpoint does not match the configured VLESS {leg} server"),
            ));
        }
        if endpoint.addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("resolved VLESS {leg} endpoint has no addresses"),
            ));
        }
        Ok(())
    }

    fn direct_paths(
        config: &VlessOutboundConfig,
        endpoint: ResolvedEndpoint,
        download_endpoint: Option<ResolvedEndpoint>,
        dialer: Dialer,
    ) -> io::Result<(UpstreamPath, Option<UpstreamPath>)> {
        Self::validate_endpoint(&config.address, config.port, &endpoint, "upload")?;
        let download_path = match (config.download(), download_endpoint) {
            (None, None) => None,
            (None, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a download endpoint was provided without VLESS download-settings",
                ));
            }
            (Some(download), supplied) => {
                let resolved = match supplied {
                    Some(resolved) => resolved,
                    None if download.address == config.address && download.port == config.port => {
                        endpoint.clone()
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "distinct VLESS download server requires a prepared download endpoint",
                        ));
                    }
                };
                Self::validate_endpoint(&download.address, download.port, &resolved, "download")?;
                Some(UpstreamPath::direct(resolved, dialer.clone()))
            }
        };
        Ok((UpstreamPath::direct(endpoint, dialer), download_path))
    }

    fn download_path_from_primary(
        config: &VlessOutboundConfig,
        primary: &UpstreamPath,
    ) -> io::Result<Option<UpstreamPath>> {
        let Some(download) = config.download() else {
            return Ok(None);
        };
        match primary {
            UpstreamPath::Proxy(_) | UpstreamPath::LazyDirect { .. } => Ok(Some(primary.clone())),
            UpstreamPath::Direct { endpoint, .. }
            | UpstreamPath::Group {
                endpoint: Some(endpoint),
                ..
            } if endpoint.logical_host == download.address && endpoint.port == download.port => {
                Ok(Some(primary.clone()))
            }
            UpstreamPath::Group { endpoint: None, .. } => Ok(Some(primary.clone())),
            UpstreamPath::Direct { .. } | UpstreamPath::Group { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "distinct VLESS download server requires an explicit download upstream path",
            )),
        }
    }

    fn assemble(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        upload_security: SecurityClient,
        download_security: Option<SecurityClient>,
    ) -> io::Result<Self> {
        Self::assemble_with_xhttp(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
            |config| Ok(XHttpClient::new(config)),
        )
    }

    fn assemble_with_xhttp_limits(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        upload_security: SecurityClient,
        download_security: Option<SecurityClient>,
        send_buffer_size: usize,
        upload_chunk_size: usize,
    ) -> io::Result<Self> {
        Self::assemble_with_xhttp(
            config,
            upload_path,
            download_path,
            upload_security,
            download_security,
            |config| XHttpClient::new_with_limits(config, send_buffer_size, upload_chunk_size),
        )
    }

    fn assemble_with_xhttp(
        config: &VlessOutboundConfig,
        upload_path: UpstreamPath,
        download_path: Option<UpstreamPath>,
        upload_security: SecurityClient,
        download_security: Option<SecurityClient>,
        mut build_xhttp: impl FnMut(XHttpConfig) -> io::Result<XHttpClient>,
    ) -> io::Result<Self> {
        let encryption = match &config.encryption {
            crate::config::VlessEncryption::None => None,
            crate::config::VlessEncryption::MlKem768X25519Plus(value) => {
                Some(super::encryption::Client::parse(value)?)
            }
        };
        let mode = match config
            .xhttp()
            .map(|config| config.mode)
            .unwrap_or(ConfigXHttpMode::PacketUp)
        {
            ConfigXHttpMode::PacketUp => XHttpMode::PacketUp,
            ConfigXHttpMode::StreamOne => XHttpMode::StreamOne,
            ConfigXHttpMode::StreamUp => XHttpMode::StreamUp,
        };
        if mode == XHttpMode::StreamOne && config.download().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP stream-one cannot use download settings",
            ));
        }
        let xhttp = config
            .xhttp()
            .map(|config| {
                let mut request = XHttpConfig::new(config.host.clone(), config.path.clone(), mode)?;
                request.headers = config.headers.clone();
                request.request = config.request.clone();
                request.http_version = config.http_version;
                request.reuse = config.reuse.clone();
                build_xhttp(request)
            })
            .transpose()?;
        let download = match (config.download(), download_path, download_security) {
            (None, None, None) => None,
            (Some(config), Some(upstream), Some(security)) => Some(VlessDownloadLeg {
                transport: VlessTransportLeg {
                    server: server_destination(&config.address, config.port)?,
                    upstream,
                    security,
                },
                xhttp: {
                    let mut request =
                        XHttpConfig::new(config.host.clone(), config.path.clone(), mode)?;
                    request.headers = config.headers.clone();
                    request.request = config.request.clone();
                    request.http_version = config.http_version;
                    request.reuse = config.reuse.clone();
                    build_xhttp(request)?
                },
            }),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS download configuration, path, and security must be provided together",
                ));
            }
        };
        let transport = match &config.transport {
            VlessTransport::Stream(transport) => transport.clone(),
            VlessTransport::Xhttp(_) => StreamTransport::Tcp,
        };
        Ok(Self {
            uuid: config.id,
            encryption,
            upload: VlessTransportLeg {
                server: server_destination(&config.address, config.port)?,
                upstream: upload_path,
                security: upload_security,
            },
            xhttp,
            download,
            encoding: config.packet_encoding,
            cancellation: CancellationToken::new(),
            stream_options: config.stream_options.clone(),
            tasks: TaskTracker::new(),
            grpc_pool: match &transport {
                StreamTransport::Grpc { options, .. } => {
                    Some(crate::transport::GrpcPool::new(options.clone()))
                }
                _ => None,
            },
            transport,
            vision: config.flow == "xtls-rprx-vision",
            vision_stats: Arc::default(),
        })
    }

    fn connect_transport<'a>(
        &'a self,
        session: StreamSession,
        context: &'a EstablishContext,
    ) -> futures_util::future::BoxFuture<'a, Result<BoxStream, DispatchError>> {
        Box::pin(async move {
            let Some(xhttp) = &self.xhttp else {
                return Self::connect_transport_leg(&self.upload, session, context).await;
            };
            let upload = || {
                let session = session.clone();
                async move {
                    Self::connect_xhttp_leg(&self.upload, xhttp.http_version(), session, context)
                        .await
                        .map_err(io::Error::other)
                }
            };
            let Some(download) = &self.download else {
                let connected = context
                    .run_io(
                        "VLESS XHTTP handshake",
                        xhttp.open_transport(context.deadline(), upload),
                    )
                    .await?;
                tracing::debug!(stage = "xhttp", "VLESS transport stage completed");
                return Ok(connected);
            };

            let download_stream = || {
                let session = session.clone();
                async move {
                    Self::connect_xhttp_leg(
                        &download.transport,
                        download.xhttp.http_version(),
                        session,
                        context,
                    )
                    .await
                    .map_err(io::Error::other)
                }
            };
            let connected = context
                .run_io(
                    "VLESS XHTTP handshake",
                    xhttp.open_with_download_transports(
                        context.deadline(),
                        &download.xhttp,
                        upload,
                        download_stream,
                    ),
                )
                .await?;
            tracing::debug!(stage = "xhttp-split", "VLESS transport stage completed");
            Ok(connected)
        })
    }

    async fn prepare(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<PreparedStream, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        tokio::select! {biased;
            ()=self.cancellation.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                let mut vision_control=None;
                let (raw,transport)=if self.vision && self.encryption.is_none() {
                    let raw=self.upload.upstream.connect_server(session,&self.upload.server,context).await?.io;
                    let (raw,control)=context.run_io("Vision TLS handshake",self.upload.security.connect_vision(raw,self.vision_stats.clone())).await?;
                    vision_control=Some(control);
                    (raw,StreamTransport::Tcp)
                } else if let StreamTransport::Grpc{uri,..}=&self.transport {
                    let io=self.grpc_pool.as_ref().expect("gRPC pool").open(uri,context.deadline(),||async {
                        self.connect_transport(session,context).await.map_err(io::Error::other)
                    }).await?;
                    (io,StreamTransport::Tcp)
                } else {(self.connect_transport(session,context).await?,self.transport.clone())};
                if self.vision && self.encryption.is_some() {
                    vision_control=Some(crate::security::vision::SpliceControl::default());
                }
                let encryption=self.encryption.as_ref().map(|client| {
                    client.start().map(|flight| flight.with_vision(
                        vision_control.as_ref().map(|control| (control.clone(),self.vision_stats.clone()))
                    ))
                }).transpose()?;
                let token=self.cancellation.child_token();
                Ok(PreparedStream { raw:Box::new(crate::outbound::owned_stream::OwnedStream::new(raw,token.clone())),
                    id:self.uuid, encryption, transport, options:self.stream_options.clone(), vision_control, deadline:context.deadline(), tasks:self.tasks.clone(), token })
            }=>result,
        }
    }

    #[cfg(feature = "interop-test")]
    #[doc(hidden)]
    pub fn vision_raw_bytes(&self) -> (u64, u64) {
        self.vision_stats.bytes()
    }

    /// Read-only native frame counters, absent from production builds.
    #[cfg(feature = "interop-test")]
    #[doc(hidden)]
    pub fn xhttp_quic_ping_counts(&self) -> (Vec<u64>, Vec<u64>) {
        (
            self.xhttp
                .as_ref()
                .map_or_else(Vec::new, XHttpClient::quic_pings),
            self.download
                .as_ref()
                .map_or_else(Vec::new, |leg| leg.xhttp.quic_pings()),
        )
    }

    async fn connect_transport_leg(
        leg: &VlessTransportLeg,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        let raw = leg
            .upstream
            .connect_server(session, &leg.server, context)
            .await?;
        tracing::debug!(stage = "upstream", "VLESS transport stage completed");
        let secured = context
            .run_io(
                "VLESS TLS/REALITY handshake",
                leg.security.connect_with_context(raw.io, context),
            )
            .await?;
        tracing::debug!(stage = "security", "VLESS transport stage completed");
        Ok(secured)
    }

    fn connect_xhttp_leg<'a>(
        leg: &'a VlessTransportLeg,
        version: crate::config::XHttpVersion,
        session: StreamSession,
        context: &'a EstablishContext,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<crate::transport::xhttp::TransportIo, DispatchError>,
    > {
        // Separate the per-leg handshake state from both parent futures. A
        // split XHTTP setup otherwise duplicates the largest TLS/QUIC branch
        // throughout try_join/acquire on the runtime's bounded thread stack.
        Box::pin(async move {
            use crate::{
                dispatch::DatagramBudget,
                transport::xhttp::{QuicTransport, TransportIo},
            };
            if version != crate::config::XHttpVersion::Http3 {
                return Self::connect_transport_leg(leg, session, context)
                    .await
                    .map(TransportIo::Stream);
            }
            let (tls, server_name) = leg.security.quic_config_with_context(context).await?;
            let server = leg.upstream.datagram_server(&leg.server, context).await?;
            let peer = context.resolve_ip(&server).await?;
            let budget = DatagramBudget::new(1400, 1400);
            let request =
                DatagramRequest::new(DatagramSession::new(session.inbound, session.source))
                    .with_budget(budget);
            let transport = leg.upstream.open_datagram(request, context).await?;
            Ok(TransportIo::Quic(Box::new(QuicTransport {
                transport,
                peer,
                budget,
                tls,
                server_name,
            })))
        })
    }
}
pub(super) struct PreparedStream {
    raw: BoxStream,
    encryption: Option<super::encryption::Handshake>,
    id: uuid::Uuid,
    transport: StreamTransport,
    options: crate::config::VlessStreamOptions,
    vision_control: Option<crate::security::vision::SpliceControl>,
    pub(super) deadline: tokio::time::Instant,
    tasks: TaskTracker,
    pub(super) token: CancellationToken,
}
impl PreparedStream {
    pub(super) async fn finish(
        self,
        command: VlessCommand,
        target: Option<&crate::session::Destination>,
    ) -> Result<BoxStream, DispatchError> {
        let deadline = self.deadline;
        if tokio::time::Instant::now() >= deadline {
            return Err(DispatchError::TimedOut);
        }
        let mut header =
            super::codec::encode_header(self.id, command, target, self.vision_control.is_some())?;
        let initial = self.encryption.as_ref().map_or_else(
            || header.clone(),
            |flight| bytes::Bytes::copy_from_slice(flight.prefix()),
        );
        let token = self.token.clone();
        let guard = token.clone().drop_guard();
        let stream = tokio::time::timeout_at(deadline, async {
            let mut raw = self.raw;
            let mut driver = None;
            let mut prefix_sent = false;
            match &self.transport {
                StreamTransport::Tcp => {}
                StreamTransport::WebSocket { .. } => {
                    if self.options.http_upgrade {
                        raw = crate::transport::http_upgrade(
                            raw,
                            &self.transport.websocket_options()?.expect("validated WS"),
                            &initial,
                            self.options.fast_open,
                            deadline,
                        )
                        .await?;
                    } else {
                        raw = crate::transport::connect_websocket(
                            raw,
                            &self.transport.websocket_options()?.expect("validated WS"),
                            &initial,
                            deadline,
                        )
                        .await?;
                    }
                    prefix_sent = true;
                    if self.encryption.is_none() {
                        header = bytes::Bytes::new();
                    }
                }
                StreamTransport::Http { .. } => {
                    raw = crate::transport::http_obfs(
                        raw,
                        &self.transport.http_options()?.expect("validated HTTP"),
                        &initial,
                        deadline,
                    )
                    .await?;
                    prefix_sent = true;
                    if self.encryption.is_none() {
                        header = bytes::Bytes::new();
                    }
                }
                StreamTransport::Grpc { .. } => unreachable!("gRPC opened during prepare"),
                StreamTransport::H2 { uris } => {
                    let connected = crate::transport::legacy_h2(
                        raw,
                        &uris[rand::random_range(0..uris.len())],
                        deadline,
                    )
                    .await?;
                    raw = connected.0;
                    driver = Some(connected.1);
                }
            }
            if let Some(driver) = driver {
                let token = token.clone();
                let observation = crate::resources::observation::track(
                    crate::resources::observation::ResourceKind::Task,
                );
                self.tasks
                    .spawn(crate::resources::observation::bind(async move {
                        let _observation = observation;
                        token.cancelled().await;
                        let _ = driver.stop().await;
                    }));
            }
            if let Some(flight) = self.encryption {
                raw = flight.finish(raw, prefix_sent, deadline).await?;
            }
            let stream = VlessStream::with_deadline(raw, header, deadline);
            let stream: BoxStream =
                Box::new(if matches!(self.transport, StreamTransport::Http { .. }) {
                    stream.with_whole_close()
                } else {
                    stream
                });
            let stream = if let Some(control) = self.vision_control {
                Box::new(super::vision::VisionStream::new(stream, self.id, control)) as BoxStream
            } else {
                stream
            };
            Ok::<BoxStream, io::Error>(Box::new(crate::outbound::owned_stream::OwnedStream::new(
                stream, token,
            )))
        })
        .await
        .map_err(|_| DispatchError::TimedOut)??;
        guard.disarm();
        Ok(stream)
    }
}
#[async_trait]
impl OutboundConnector for VlessOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let prepared = self.prepare(session, context).await?;
        let io = prepared
            .finish(VlessCommand::Tcp, Some(&effective_peer))
            .await?;
        Ok(ConnectedStream { io, effective_peer })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let prepared = self
            .prepare(
                StreamSession {
                    metadata: request.session.metadata.clone(),
                    inbound: request.session.inbound,
                    source: request.session.source,
                    destination: self.upload.server.clone(),
                    sniffed_domain: None,
                },
                context,
            )
            .await?;
        let transport: Box<dyn DatagramTransport> = if self.encoding == VlessPacketEncoding::Xudp {
            let mut io = prepared.finish(VlessCommand::Mux, None).await?;
            context.run_io("VLESS XUDP request", io.flush()).await?;
            let transport = XudpTransport::with_budget(io, [0; 8], request.budget());
            // Every XHTTP version independently drives accepted body writes
            // through bounded queues. Per-frame flush would serialize XUDP
            // packets into separate timer-delayed packet-up POSTs. Encryption
            // may add a buffered writer, so retain its conservative contract.
            Box::new(if self.encryption.is_none() && self.xhttp.is_some() {
                transport.with_autonomous_writes()
            } else {
                transport
            })
        } else {
            Box::new(super::datagram::VlessDatagram::new(
                prepared,
                self.encoding == VlessPacketEncoding::PacketAddr,
                request.budget(),
                context.resolution(),
            ))
        };
        Ok(crate::dispatch::bound_datagram(transport, request.budget()))
    }
    fn begin_shutdown(&self) {
        self.cancellation.cancel();
        if let Some(encryption) = &self.encryption {
            encryption.close();
        }
        if let Some(pool) = &self.grpc_pool {
            pool.begin_shutdown();
        }
        if let Some(xhttp) = &self.xhttp {
            xhttp.begin_stop();
        }
        if let Some(download) = &self.download {
            download.xhttp.begin_stop();
        }
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.close();
        self.tasks.wait().await;
        if let Some(pool) = &self.grpc_pool {
            pool.shutdown().await;
        }
        if let Some(xhttp) = &self.xhttp {
            xhttp.stop().await;
        }
        if let Some(download) = &self.download {
            download.xhttp.stop().await;
        }
    }
}
impl Drop for VlessOutbound {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(encryption) = &self.encryption {
            encryption.close();
        }
    }
}

#[async_trait]
impl Dispatcher for VlessOutbound {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        OutboundConnector::connect_stream(self, session, &EstablishContext::default())
            .await
            .map(|connected| connected.io)
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        OutboundConnector::open_datagram(
            self,
            DatagramRequest::new(session),
            &EstablishContext::default(),
        )
        .await
    }
}

#[cfg(all(test, feature = "outbound-socks5", feature = "outbound-vless"))]
mod connector_composition_tests {
    use super::*;
    use crate::{
        config::{
            SecurityConfig, Socks5OutboundConfig, TlsConfig, VlessEncryption, VlessOutboundConfig,
            XHttpConfig as ConfigXHttpConfig, XHttpDownloadConfig, XHttpMode as ConfigXHttpMode,
        },
        dispatch::{DatagramTransport, DispatchError},
        session::StreamSession,
    };

    struct NeverConnector;

    #[async_trait]
    impl OutboundConnector for NeverConnector {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            Err(DispatchError::NetworkUnreachable)
        }

        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NetworkUnreachable)
        }
    }

    fn vless_config(address: &str) -> VlessOutboundConfig {
        VlessOutboundConfig {
            address: address.to_owned(),
            port: 443,
            id: uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
            encryption: VlessEncryption::None,
            flow: String::new(),
            security: SecurityConfig::Tls(TlsConfig::xhttp(address.to_owned())),
            transport: crate::config::VlessTransport::Xhttp(Box::new(ConfigXHttpConfig {
                path: "/xhttp".to_owned(),
                host: address.to_owned(),
                mode: ConfigXHttpMode::PacketUp,
                http_version: Default::default(),
                reuse: None,
                headers: Default::default(),
                request: Default::default(),
                download: None,
            })),
            packet_encoding: crate::config::VlessPacketEncoding::Xudp,
            stream_options: Default::default(),
        }
    }

    fn socks_config(address: &str) -> Socks5OutboundConfig {
        Socks5OutboundConfig {
            tls: None,
            address: address.to_owned(),
            port: 1080,
            username: None,
            password: None,
        }
    }

    fn split_vless_config(upload: &str, download: &str, download_port: u16) -> VlessOutboundConfig {
        let mut config = vless_config(upload);
        let crate::config::VlessTransport::Xhttp(xhttp) = &mut config.transport else {
            unreachable!()
        };
        xhttp.download = Some(Box::new(XHttpDownloadConfig {
            address: download.to_owned(),
            port: download_port,
            security: SecurityConfig::Tls(TlsConfig::xhttp(download.to_owned())),
            http_version: Default::default(),
            reuse: None,
            path: "/download".to_owned(),
            host: download.to_owned(),
            headers: Default::default(),
            request: Default::default(),
        }));
        config
    }

    fn endpoint(address: &str, port: u16) -> ResolvedEndpoint {
        ResolvedEndpoint {
            logical_host: address.to_owned(),
            port,
            addresses: vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))],
        }
    }

    #[test]
    fn all_two_hop_protocol_combinations_build_as_connector_graphs() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "VLESS-REGRESSION",
            "all_two_hop_protocol_combinations_build_as_connector_graphs",
        );
        let physical: Arc<dyn OutboundConnector> = Arc::new(NeverConnector);
        let vless_leaf: Arc<dyn OutboundConnector> = Arc::new(
            VlessOutbound::new_with_upstream(&vless_config("vless-leaf.example"), physical.clone())
                .unwrap(),
        );
        let socks_leaf: Arc<dyn OutboundConnector> = Arc::new(
            Socks5Outbound::new_with_upstream(&socks_config("socks-leaf.example"), physical)
                .unwrap(),
        );

        let combinations: [Arc<dyn OutboundConnector>; 4] = [
            Arc::new(
                VlessOutbound::new_with_upstream(
                    &vless_config("vless-over-vless.example"),
                    vless_leaf.clone(),
                )
                .unwrap(),
            ),
            Arc::new(
                VlessOutbound::new_with_upstream(
                    &vless_config("vless-over-socks.example"),
                    socks_leaf.clone(),
                )
                .unwrap(),
            ),
            Arc::new(
                Socks5Outbound::new_with_upstream(
                    &socks_config("socks-over-vless.example"),
                    vless_leaf,
                )
                .unwrap(),
            ),
            Arc::new(
                Socks5Outbound::new_with_upstream(
                    &socks_config("socks-over-socks.example"),
                    socks_leaf,
                )
                .unwrap(),
            ),
        ];
        assert_eq!(combinations.len(), 4);
    }

    #[test]
    fn direct_download_constructor_reuses_or_requires_the_precise_prepared_endpoint() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "VLESS-REGRESSION",
            "direct_download_constructor_reuses_or_requires_the_precise_prepared_endpoint",
        );
        let same = split_vless_config("same.example", "same.example", 443);
        let outbound =
            VlessOutbound::new(&same, endpoint("same.example", 443), Dialer::default()).unwrap();
        assert!(outbound.download.is_some());

        let mut invalid_mode = same.clone();
        let crate::config::VlessTransport::Xhttp(xhttp) = &mut invalid_mode.transport else {
            unreachable!()
        };
        xhttp.mode = ConfigXHttpMode::StreamOne;
        let error = VlessOutbound::new(
            &invalid_mode,
            endpoint("same.example", 443),
            Dialer::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("stream-one"));

        let distinct = split_vless_config("upload.example", "download.example", 8443);
        let error = VlessOutbound::new(
            &distinct,
            endpoint("upload.example", 443),
            Dialer::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("prepared download endpoint"));

        let outbound = VlessOutbound::new_with_endpoints(
            &distinct,
            endpoint("upload.example", 443),
            Some(endpoint("download.example", 8443)),
            Dialer::default(),
        )
        .unwrap();
        let download = outbound.download.as_ref().unwrap();
        assert_eq!(outbound.upload.server.port(), 443);
        assert_eq!(download.transport.server.port(), 8443);
    }

    #[test]
    fn split_node_over_a_proxy_automatically_reuses_its_parent_for_both_legs() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "VLESS-REGRESSION",
            "split_node_over_a_proxy_automatically_reuses_its_parent_for_both_legs",
        );
        let parent: Arc<dyn OutboundConnector> = Arc::new(NeverConnector);
        let config = split_vless_config("upload.example", "download.example", 8443);
        let outbound = VlessOutbound::new_with_upstream(&config, parent).unwrap();
        let UpstreamPath::Proxy(upload_parent) = &outbound.upload.upstream else {
            panic!("upload leg must use the configured parent")
        };
        let UpstreamPath::Proxy(download_parent) =
            &outbound.download.as_ref().unwrap().transport.upstream
        else {
            panic!("download leg must use the configured parent")
        };
        assert!(Arc::ptr_eq(upload_parent, download_parent));
    }
}
