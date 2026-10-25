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

fn static_h2_security(config: &crate::config::SecurityConfig) -> bool {
    match config {
        crate::config::SecurityConfig::Jls(_) => true,
        crate::config::SecurityConfig::Reality(_) => true,
        crate::config::SecurityConfig::Tls(tls) => {
            tls.identity
                .as_ref()
                .is_none_or(|identity| identity.origin.is_none())
                && tls.ech.as_ref().is_none_or(|ech| !ech.is_dynamic())
        }
        _ => false,
    }
}

impl VlessTransportLeg {
    async fn h2_lease<'a>(
        &self,
        client: &'a XHttpClient,
        context: &EstablishContext,
    ) -> Result<(std::borrow::Cow<'a, XHttpClient>, Option<CancellationToken>), DispatchError> {
        if !client.uses_active_h2_reuse() || context.captures_tcp_control() {
            return Ok((client.h2_lease(false), None));
        }
        let Some(dialer) = self.upstream.static_h2_dialer(&self.server) else {
            return Ok((client.h2_lease(false), None));
        };
        let cancellation = dialer.h2_reuse_cancellation();
        let preflight = async {
            dialer.validate_egress().map_err(DispatchError::from)?;
            if tokio::time::Instant::now() >= context.deadline() {
                return Err(DispatchError::TimedOut);
            }
            // Prepared Direct never used the resolver; preserve that contract.
            let endpoint = match &self.upstream {
                UpstreamPath::Direct { endpoint, .. } => endpoint.clone(),
                _ => {
                    context
                        .resolution()
                        .with_ip_version(dialer.ip_version())
                        .with_physical_dialer(dialer)
                        .resolve_proxy(&self.server, context.deadline())
                        .await?
                }
            };
            dialer
                .validate_connected_endpoint(&endpoint)
                .map_err(DispatchError::from)?;
            if dialer
                .ordered_connected_addresses(&endpoint.addresses)
                .is_empty()
            {
                return Err(DispatchError::HostUnreachable);
            }
            Ok((client.h2_lease(true), Some(cancellation.clone())))
        };
        tokio::select! { biased;
            () = cancellation.cancelled() => Err(h2_scope_closed()),
            result = preflight => result,
        }
    }
}

fn h2_scope_closed() -> DispatchError {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "socket initialization cancelled",
    )
    .into()
}

async fn h2_scope_cancelled(scope: Option<&CancellationToken>) {
    match scope {
        Some(scope) => scope.cancelled().await,
        None => std::future::pending().await,
    }
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
                | crate::config::SecurityConfig::ShadowTls(_)
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
        let mut outbound = Self {
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
                StreamTransport::Grpc { options, .. } => Some(
                    crate::transport::GrpcPool::new_client_first(options.clone()),
                ),
                _ => None,
            },
            transport,
            vision: config.flow == "xtls-rprx-vision",
            vision_stats: Arc::default(),
        };
        let active_h2_pair = mode == XHttpMode::PacketUp
            && static_h2_security(&config.security)
            && config.xhttp().is_some_and(|settings| {
                settings.http_version == crate::config::XHttpVersion::Http2
            })
            && config.download().is_some_and(|settings| {
                settings.http_version == crate::config::XHttpVersion::Http2
                    && static_h2_security(&settings.security)
            });
        if active_h2_pair {
            if outbound
                .upload
                .upstream
                .static_h2_dialer(&outbound.upload.server)
                .is_some()
                && let Some(client) = &mut outbound.xhttp
            {
                client.enable_active_h2_reuse();
            }
            if let Some(download) = &mut outbound.download
                && download
                    .transport
                    .upstream
                    .static_h2_dialer(&download.transport.server)
                    .is_some()
            {
                download.xhttp.enable_active_h2_reuse();
            }
        }
        Ok(outbound)
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
            let (upload_client, upload_scope) = self.upload.h2_lease(xhttp, context).await?;
            let xhttp = upload_client.as_ref();
            let (download_client, download_scope) = match &self.download {
                Some(download) => {
                    let (client, scope) = download
                        .transport
                        .h2_lease(&download.xhttp, context)
                        .await?;
                    (Some(client), scope)
                }
                None => (None, None),
            };
            let operation = async {
                let upload = || {
                    let session = session.clone();
                    async move {
                        Self::connect_xhttp_leg(
                            &self.upload,
                            xhttp.http_version(),
                            session,
                            context,
                        )
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
                            download_client.as_deref().expect("download client"),
                            upload,
                            download_stream,
                        ),
                    )
                    .await?;
                tracing::debug!(stage = "xhttp-split", "VLESS transport stage completed");
                Ok(connected)
            };
            tokio::select! { biased;
                () = h2_scope_cancelled(upload_scope.as_ref()) => Err(h2_scope_closed()),
                () = h2_scope_cancelled(download_scope.as_ref()) => Err(h2_scope_closed()),
                result = operation => result,
            }
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
    #[cfg(test)]
    pub(super) fn for_memory_test(
        raw: BoxStream,
        deadline: tokio::time::Instant,
        token: CancellationToken,
    ) -> Self {
        Self {
            raw,
            encryption: None,
            id: uuid::Uuid::from_bytes([7; 16]),
            transport: StreamTransport::Tcp,
            options: Default::default(),
            vision_control: None,
            deadline,
            tasks: TaskTracker::new(),
            token,
        }
    }

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
        } else if self.encoding == VlessPacketEncoding::PacketAddr {
            let transport = super::datagram::VlessDatagram::packet_addr(
                prepared,
                request.budget(),
                context.resolution(),
            )
            .await?;
            Box::new(if self.encryption.is_none() && self.xhttp.is_some() {
                transport.with_autonomous_writes()
            } else {
                transport
            })
        } else {
            Box::new(super::datagram::VlessDatagram::new(
                prepared,
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

#[cfg(test)]
mod active_h2_memory_tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Downloads = Arc<Mutex<HashMap<String, h2::SendStream<bytes::Bytes>>>>;

    // Config -> production pool selection only. The memory peer below does
    // not perform native REALITY authentication; real TUN verifies it separately.
    fn with_static_reality(mut raw: serde_json::Value, reality: bool) -> serde_json::Value {
        if reality {
            raw["proxies"][0]["servername"] = serde_json::json!("memory.invalid");
            raw["proxies"][0]["reality-opts"] = serde_json::json!({
                "public-key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
                "short-id": "00"
            });
        }
        raw
    }

    // The two physical legs share one synthetic handler, never a host socket.
    async fn peer(
        calls: &AtomicUsize,
        tasks: &TaskTracker,
        downloads: Downloads,
        max_concurrent_streams: Option<u32>,
    ) -> io::Result<BoxStream> {
        calls.fetch_add(1, Ordering::Relaxed);
        let (io, remote) = tokio::io::duplex(16384);
        tasks.spawn(async move {
            let mut builder = h2::server::Builder::new();
            if let Some(maximum) = max_concurrent_streams {
                builder.max_concurrent_streams(maximum);
            }
            let mut connection = builder.handshake(remote).await.unwrap();
            let requests = TaskTracker::new();
            while let Some(Ok((request, mut reply))) = connection.accept().await {
                let path = request.uri().path().to_owned();
                if request.method() == http::Method::GET {
                    let mut body = reply.send_response(http::Response::new(()), false).unwrap();
                    body.send_data(bytes::Bytes::from_static(b"ready"), false)
                        .unwrap();
                    downloads.lock().unwrap().insert(path, body);
                } else {
                    let downloads = downloads.clone();
                    requests.spawn(async move {
                        let session = path.rsplit_once('/').unwrap().0;
                        let mut body = request.into_body();
                        while let Some(Ok(data)) = body.data().await {
                            body.flow_control().release_capacity(data.len()).unwrap();
                            downloads
                                .lock()
                                .unwrap()
                                .get_mut(session)
                                .unwrap()
                                .send_data(data, false)
                                .unwrap();
                        }
                        reply.send_response(http::Response::new(()), true).unwrap();
                    });
                }
            }
            requests.close();
            requests.wait().await;
        });
        Ok(Box::new(io))
    }

    // Apply only after the production scope helper; not part of the old-source RED.
    #[cfg(all(target_os = "linux", feature = "sing-mux"))]
    #[tokio::test]
    async fn private_split_h2_control_fallback_and_dialer_stop_do_not_take_cached_sender() {
        run_private_split_h2_control_case(false).await;
    }

    #[cfg(all(target_os = "linux", feature = "sing-mux"))]
    #[tokio::test]
    async fn private_split_h2_reality_control_fallback_and_dialer_stop_do_not_take_cached_sender() {
        run_private_split_h2_control_case(true).await;
    }

    #[cfg(all(target_os = "linux", feature = "sing-mux"))]
    async fn run_private_split_h2_control_case(reality: bool) {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "XHTTP-UNIT",
            if reality {
                "private_split_h2_reality_control_fallback_and_dialer_stop_do_not_take_cached_sender"
            } else {
                "private_split_h2_control_fallback_and_dialer_stop_do_not_take_cached_sender"
            },
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            let probe = crate::resources::observation::ResourceProbe::default();
            let result = probe.scope(async {
                let raw = serde_json::json!({"mixed-port":1080,"proxies":[{"name":"peer","type":"vless","server":"192.0.2.1","port":443,"uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,"alpn":["h2"],"xhttp-opts":{"mode":"packet-up","path":"/x","download-settings":{"server":"192.0.2.2","path":"/x"}}}],"rules":["MATCH,peer"]});
                let raw = with_static_reality(raw, reality);
                let config = crate::config::Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
                let crate::config::ProxyProtocol::Vless(config) = &config.proxies[0].protocol else { unreachable!() };
                let outbound = VlessOutbound::new_with_path(config, UpstreamPath::LazyDirect { dialer: Dialer::default() }).unwrap();
                let client = outbound.xhttp.as_ref().unwrap();
                let download = &outbound.download.as_ref().unwrap().xhttp;
                let tasks = TaskTracker::new();
                let uploads = AtomicUsize::new(0);
                let downloads = AtomicUsize::new(0);
                let handler: Downloads = Default::default();
                let context = EstablishContext::default();
                let (warm_client, _) = outbound.upload.h2_lease(client, &context).await.unwrap();
                let mut warm = warm_client.open_with_download(context.deadline(), download,
                    || peer(&uploads, &tasks, handler.clone(), None), || peer(&downloads, &tasks, handler.clone(), None)).await.unwrap();
                let mut greeting = [0; 5];
                warm.read_exact(&mut greeting).await.unwrap();
                warm.write_all(b"prime").await.unwrap();
                warm.flush().await.unwrap();
                let mut prime = [0; 5];
                warm.read_exact(&mut prime).await.unwrap();
                let warm_count = (uploads.load(Ordering::Relaxed), downloads.load(Ordering::Relaxed));
                let controlled = context.capture_tcp_control(crate::dialer::tcp_control::Capture::default());
                let mut streams = Vec::new();
                for _ in 0..2 {
                    let (fresh, _) = outbound.upload.h2_lease(client, &controlled).await.unwrap();
                    let mut stream = fresh.open_with_download(controlled.deadline(), download,
                        || peer(&uploads, &tasks, handler.clone(), None), || peer(&downloads, &tasks, handler.clone(), None)).await.unwrap();
                    stream.read_exact(&mut greeting).await.unwrap();
                    streams.push(stream);
                }
                let fallback_count = (uploads.load(Ordering::Relaxed), downloads.load(Ordering::Relaxed));
                let UpstreamPath::LazyDirect { dialer } = &outbound.upload.upstream else { unreachable!() };
                dialer.begin_shutdown();
                let attempt = async {
                    let (leased, _) = outbound.upload.h2_lease(client, &context).await?;
                    leased.open_with_download(context.deadline(), download,
                        || peer(&uploads, &tasks, handler.clone(), None), || peer(&downloads, &tasks, handler.clone(), None)).await.map_err(DispatchError::from)
                }.await;
                let cancelled = matches!(attempt, Err(DispatchError::Other(message)) if message == "socket initialization cancelled");
                let after_stop = (uploads.load(Ordering::Relaxed), downloads.load(Ordering::Relaxed));
                let mut first = streams.remove(0);
                first.shutdown().await.unwrap();
                drop(first);
                warm.write_all(b"alive").await.unwrap();
                warm.flush().await.unwrap();
                let mut echo = [0; 5];
                warm.read_exact(&mut echo).await.unwrap();
                outbound.shutdown().await;
                let stopped = warm.read(&mut [0; 1]).await;
                drop(warm);
                drop(streams);
                tasks.close();
                tasks.wait().await;
                (warm_count, fallback_count, after_stop, cancelled, greeting, prime, echo, stopped, probe.snapshot().is_idle())
            }).await;
            let (warm, fallback, after_stop, cancelled, greeting, prime, echo, stopped, idle) = result;
            assert_eq!(&greeting, b"ready", "fallback H2 fixture failed");
            assert_eq!(&prime, b"prime", "warm upload SETTINGS/POST fixture failed");
            assert_eq!(&echo, b"alive", "fallback close or initializer Stop killed an established sibling");
            assert!(matches!(stopped, Ok(0) | Err(_)) && idle, "node Stop did not release its fallback owners");
            assert!(cancelled, "stopped Dialer took a cached H2 sender");
            assert_eq!((warm, fallback, after_stop), ((1, 1), (3, 1), (3, 1)), "TCP-control acquisition reused a physical socket or stopped Dialer dialed again");
        }).await.expect("fallback H2 owners did not stop");
    }

    #[tokio::test]
    async fn private_split_h2_shares_four_active_leases_and_stops_both_legs() {
        run_private_split_h2_share_case(false).await;
    }

    #[tokio::test]
    async fn private_split_h2_reality_qualification_shares_four_active_leases_and_stops_both_legs()
    {
        run_private_split_h2_share_case(true).await;
    }

    async fn run_private_split_h2_share_case(reality: bool) {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "XHTTP-UNIT",
            if reality {
                "private_split_h2_reality_qualification_shares_four_active_leases_and_stops_both_legs"
            } else {
                "private_split_h2_shares_four_active_leases_and_stops_both_legs"
            },
        );
        tokio::time::timeout(Duration::from_secs(8), async {
            // Explicit reuse is the existing control; omitted reuse is the new behavior.
            for explicit in [true, false] {
                let probe = crate::resources::observation::ResourceProbe::default();
                let result = probe.scope(async {
                    let mut options = serde_json::json!({"mode":"packet-up", "path":"/x", "download-settings":{"server":"192.0.2.2", "path":"/x"}});
                    if explicit {
                        let reuse = serde_json::json!({"max-concurrency":"4"});
                        options["reuse-settings"] = reuse.clone();
                        options["download-settings"]["reuse-settings"] = reuse;
                    }
                    let raw = serde_json::json!({"mixed-port":1080, "proxies":[{"name":"peer", "type":"vless", "server":"192.0.2.1", "port":443, "uuid":"07070707-0707-0707-0707-070707070707", "network":"xhttp", "tls":true, "alpn":["h2"], "xhttp-opts":options}], "rules":["MATCH,peer"]});
                    let raw = with_static_reality(raw, reality);
                    let config = crate::config::Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
                    let crate::config::ProxyProtocol::Vless(config) = &config.proxies[0].protocol else { unreachable!() };
                    let outbound = VlessOutbound::new_with_path(config, UpstreamPath::LazyDirect { dialer: Dialer::default() }).unwrap();
                    let client = outbound.xhttp.as_ref().unwrap();
                    let download = &outbound.download.as_ref().unwrap().xhttp;
                    let tasks = TaskTracker::new();
                    let uploads = AtomicUsize::new(0);
                    let downloads = AtomicUsize::new(0);
                    let handler: Downloads = Default::default();
                    let open = || client.open_with_download(
                        tokio::time::Instant::now() + Duration::from_secs(2), download,
                        || peer(&uploads, &tasks, handler.clone(), None),
                        || peer(&downloads, &tasks, handler.clone(), None),
                    );
                    let count = || (uploads.load(Ordering::Relaxed), downloads.load(Ordering::Relaxed));
                    let mut streams = Vec::new();
                    let mut four = (0, 0);
                    for index in 0..5 {
                        let mut stream = open().await.unwrap();
                        let mut greeting = [0; 5];
                        stream.read_exact(&mut greeting).await.unwrap();
                        assert_eq!(&greeting, b"ready", "synthetic H2 peer fixture failed");
                        if index == 0 {
                            // Negotiate both physical legs before expecting warm sharing.
                            stream.write_all(b"prime").await.unwrap();
                            stream.flush().await.unwrap();
                            let mut echo = [0; 5];
                            stream.read_exact(&mut echo).await.unwrap();
                            assert_eq!(&echo, b"prime", "two-leg priming fixture failed");
                        }
                        streams.push(stream);
                        if index == 3 { four = count(); }
                    }
                    let five = count();
                    let mut first = streams.remove(0);
                    first.shutdown().await.unwrap();
                    drop(first);
                    streams[0].write_all(b"alive").await.unwrap();
                    streams[0].flush().await.unwrap();
                    let mut echo = [0; 5];
                    streams[0].read_exact(&mut echo).await.unwrap();
                    for stream in &mut streams { stream.shutdown().await.unwrap(); }
                    drop(streams);
                    let mut fresh = open().await.unwrap();
                    let mut greeting = [0; 5];
                    fresh.read_exact(&mut greeting).await.unwrap();
                    let after_idle = count();
                    outbound.shutdown().await;
                    let stopped = fresh.read(&mut [0; 1]).await;
                    drop(fresh);
                    tasks.close();
                    tasks.wait().await;
                    (four, five, after_idle, echo, greeting, stopped, probe.snapshot().is_idle())
                }).await;
                let (four, five, after_idle, echo, greeting, stopped, idle) = result;
                assert_eq!(&echo, b"alive", "closing one request killed its sibling");
                assert_eq!(&greeting, b"ready", "fresh physical handshake fixture failed");
                assert!(matches!(stopped, Ok(0) | Err(_)), "Stop left a readable logical stream");
                assert!(idle, "Stop did not join both private H2 owners");
                let expected_idle = if explicit { (2, 2) } else { (3, 3) };
                assert_eq!((four, five, after_idle), ((1, 1), (2, 2), expected_idle), "private split H2 must share four active leases; explicit={explicit}");
            }
        }).await.expect("memory H2 owners did not stop");
    }

    #[tokio::test]
    async fn private_split_h2_peer_stream_credit_opens_new_download_physicals() {
        run_private_split_h2_peer_credit_case(false).await;
    }

    #[tokio::test]
    async fn private_split_h2_reality_peer_stream_credit_opens_new_download_physicals() {
        run_private_split_h2_peer_credit_case(true).await;
    }

    async fn run_private_split_h2_peer_credit_case(reality: bool) {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "XHTTP-UNIT",
            if reality {
                "private_split_h2_reality_peer_stream_credit_opens_new_download_physicals"
            } else {
                "private_split_h2_peer_stream_credit_opens_new_download_physicals"
            },
        );
        let probe = crate::resources::observation::ResourceProbe::default();
        let (business, before_stop, idle) = probe
            .scope(async {
                let raw = serde_json::json!({
                    "mixed-port":1080,
                    "proxies":[{"name":"peer","type":"vless","server":"192.0.2.1",
                        "port":443,"uuid":"07070707-0707-0707-0707-070707070707",
                        "network":"xhttp","tls":true,"alpn":["h2"],
                        "xhttp-opts":{"mode":"packet-up","path":"/x",
                            "download-settings":{"server":"192.0.2.2","path":"/x"}}}],
                    "rules":["MATCH,peer"]
                });
                let raw = with_static_reality(raw, reality);
                let config = crate::config::Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
                let crate::config::ProxyProtocol::Vless(config) = &config.proxies[0].protocol
                else {
                    unreachable!()
                };
                let outbound = VlessOutbound::new_with_path(
                    config,
                    UpstreamPath::LazyDirect {
                        dialer: Dialer::default(),
                    },
                )
                .unwrap();
                let client = outbound.xhttp.as_ref().unwrap();
                let download = &outbound.download.as_ref().unwrap().xhttp;
                let tasks = TaskTracker::new();
                let uploads = AtomicUsize::new(0);
                let downloads = AtomicUsize::new(0);
                let handler: Downloads = Default::default();
                let open = || {
                    client.open_with_download(
                        tokio::time::Instant::now() + Duration::from_secs(2),
                        download,
                        || peer(&uploads, &tasks, handler.clone(), None),
                        || peer(&downloads, &tasks, handler.clone(), Some(1)),
                    )
                };
                let count = || {
                    (
                        uploads.load(Ordering::Relaxed),
                        downloads.load(Ordering::Relaxed),
                    )
                };
                let mut streams = Vec::new();
                // The deadline is only a broken-fixture fail-safe, never the RED oracle.
                let business = tokio::time::timeout(Duration::from_secs(3), async {
                    let mut first = open().await?;
                    let mut greeting = [0; 5];
                    first.read_exact(&mut greeting).await?;
                    if &greeting != b"ready" {
                        return Err(io::Error::other("first physical H2 fixture was not ready"));
                    }
                    // Prime the upload leg too, not only the download GET: initial
                    // private credit=1 may still be correct until its SETTINGS arrives.
                    first.write_all(b"prime").await?;
                    first.flush().await?;
                    let mut primed = [0; 5];
                    first.read_exact(&mut primed).await?;
                    if &primed != b"prime" {
                        return Err(io::Error::other("two-leg priming fixture failed"));
                    }
                    // Keep this GET active while both later logical opens are attempted.
                    streams.push(first);
                    let mut open_errors = Vec::new();
                    for _ in 0..2 {
                        match open().await {
                            Ok(stream) => streams.push(stream),
                            Err(error) => open_errors.push((error.kind(), error.to_string())),
                        }
                    }
                    let observed = count();
                    streams[0].write_all(b"alive").await?;
                    streams[0].flush().await?;
                    let mut sibling_echo = [0; 5];
                    streams[0].read_exact(&mut sibling_echo).await?;
                    let mut verified_extra = 0;
                    // Old code already has a non-time-based RED: wrong factory count.
                    // Do not wait for its queued GETs behind the intentionally long first GET.
                    if observed == (1, 3) && streams.len() == 3 {
                        for stream in streams.iter_mut().skip(1) {
                            let mut greeting = [0; 5];
                            stream.read_exact(&mut greeting).await?;
                            if &greeting != b"ready" {
                                return Err(io::Error::other("new physical H2 greeting differs"));
                            }
                            stream.write_all(b"extra").await?;
                            stream.flush().await?;
                            let mut echo = [0; 5];
                            stream.read_exact(&mut echo).await?;
                            if &echo != b"extra" {
                                return Err(io::Error::other("new physical H2 echo differs"));
                            }
                            verified_extra += 1;
                        }
                    }
                    Ok::<_, io::Error>((observed, open_errors, sibling_echo, verified_extra))
                })
                .await;
                let before_stop = count();
                // This runs for I/O failure and deadline expiry too, before assertions.
                outbound.shutdown().await;
                drop(streams);
                handler.lock().unwrap().clear();
                tasks.close();
                tasks.wait().await;
                (business, before_stop, probe.snapshot().is_idle())
            })
            .await;
        assert!(
            idle,
            "Stop did not join peer/physical owners; factories={before_stop:?}"
        );
        let business = business.expect("fixture timed out: not a valid factory-count RED");
        let (observed, open_errors, sibling_echo, verified_extra) =
            business.expect("fixture/first-sibling I/O failed: not a valid count RED");
        assert_eq!(&sibling_echo, b"alive", "existing sibling stopped echoing");
        assert_eq!(
            observed,
            (1, 3),
            "peer MAX_CONCURRENT_STREAMS=1 must select new download physicals; \
             before_stop={before_stop:?}; open_errors={open_errors:?}"
        );
        assert!(
            open_errors.is_empty(),
            "logical opens failed: {open_errors:?}"
        );
        assert_eq!(verified_extra, 2, "new physicals did not both deliver/echo");
    }
}
