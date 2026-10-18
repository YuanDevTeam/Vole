use crate::routing::GroupSelection;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::HashMap,
    fmt::{self, Write as _},
    future::Future,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::time::{Instant, timeout_at};

use crate::{
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{DatagramSession, Destination, StreamSession},
};

use super::DirectOutbound;
use crate::dns::resolution::{ResolutionContext, inherited_deadline};

pub const DEFAULT_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES: usize = 256;

tokio::task_local! {
    static OUTBOUND_DIAGNOSTIC: Arc<Mutex<Option<OutboundDiagnostic>>>;
}

/// One bounded, connection-local failure description for an opt-in diagnostic
/// caller. Stage names are fixed tokens and the message is the original error
/// display text truncated before it can consume unbounded memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundDiagnostic {
    stage: &'static str,
    kind: &'static str,
    message: String,
}

impl OutboundDiagnostic {
    #[must_use]
    pub(crate) const fn stage(&self) -> &'static str {
        self.stage
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> &'static str {
        self.kind
    }

    #[must_use]
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// Captures the first outbound setup failure observed while `future` runs.
///
/// The task-local slot is only installed by explicitly diagnostic local HTTP
/// callers. Normal TUN, SOCKS5, and HTTP traffic therefore pays no allocation
/// cost and cannot observe the diagnostic.
pub(crate) async fn capture_outbound_diagnostic<F>(
    future: F,
) -> (F::Output, Option<OutboundDiagnostic>)
where
    F: Future,
{
    let slot = Arc::new(Mutex::new(None));
    let output = OUTBOUND_DIAGNOSTIC.scope(slot.clone(), future).await;
    let diagnostic = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    (output, diagnostic)
}

fn record_io_diagnostic(operation: &'static str, error: &io::Error) -> String {
    let message = bounded_message(error);
    record_diagnostic(operation, io_error_kind(error.kind()), message.clone());
    message
}

fn record_dispatch_diagnostic(operation: &'static str, error: &DispatchError) {
    let message = match error {
        DispatchError::Other(message) => bounded_message(message),
        _ => bounded_message(error),
    };
    record_diagnostic(operation, error.diagnostic_code(), message);
}

fn record_timeout_diagnostic(operation: &'static str) {
    record_diagnostic(
        operation,
        "timed_out",
        "outbound setup deadline expired".to_owned(),
    );
}

fn record_diagnostic(operation: &'static str, kind: &'static str, message: String) {
    let _ = OUTBOUND_DIAGNOSTIC.try_with(|slot| {
        let mut slot = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(OutboundDiagnostic {
                stage: diagnostic_stage(operation),
                kind,
                message,
            });
        }
    });
}

fn diagnostic_stage(operation: &'static str) -> &'static str {
    match operation {
        "physical proxy-server connect" => "physical-connect",
        "direct TCP connect" => "direct-connect",
        "VLESS TLS/REALITY handshake" => "vless-security",
        "VLESS XHTTP handshake" => "vless-xhttp",
        "VLESS XUDP request header" => "vless-xudp-header",
        "SOCKS5 CONNECT handshake" => "socks5-connect",
        "SOCKS5 UDP ASSOCIATE handshake" => "socks5-udp-associate",
        "AnyTLS TLS handshake" => "anytls-tls",
        "AnyTLS authentication and session preface" => "anytls-session",
        "AnyTLS session open" => "anytls-stream",
        "Trojan TLS handshake" => "trojan-tls",
        "Trojan request header" => "trojan-request",
        "Trojan WebSocket upgrade" => "trojan-websocket",
        "Trojan gRPC handshake" => "trojan-grpc",
        _ => "outbound",
    }
}

fn io_error_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::PermissionDenied => "not_allowed",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    }
}

fn bounded_message(value: &impl fmt::Display) -> String {
    let mut output = BoundedMessage::new();
    let _ = write!(output, "{value}");
    output.value
}

struct BoundedMessage {
    value: String,
    truncated: bool,
}

impl BoundedMessage {
    fn new() -> Self {
        Self {
            value: String::with_capacity(MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES),
            truncated: false,
        }
    }

    fn truncate_to_boundary(&mut self, maximum: usize) {
        let mut length = self.value.len().min(maximum);
        while !self.value.is_char_boundary(length) {
            length -= 1;
        }
        self.value.truncate(length);
    }
}

impl fmt::Write for BoundedMessage {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        const MARKER: &str = "...";
        if self.truncated {
            return Ok(());
        }
        if self.value.len() + value.len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES {
            self.value.push_str(value);
            return Ok(());
        }

        let content_limit = MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES - MARKER.len();
        self.truncate_to_boundary(content_limit);
        let remaining = content_limit.saturating_sub(self.value.len());
        let mut length = value.len().min(remaining);
        while !value.is_char_boundary(length) {
            length -= 1;
        }
        self.value.push_str(&value[..length]);
        self.value.push_str(MARKER);
        self.truncated = true;
        Ok(())
    }
}

/// One absolute deadline shared by every hop of a logical outbound setup.
///
/// A router builds this context once and passes it through the complete
/// configured chain so nested connectors share one timeout instead of restarting it at
/// every hop.
#[derive(Debug, Clone)]
pub struct EstablishContext {
    deadline: Instant,
    resolution: ResolutionContext,
    selections: Arc<Mutex<SelectionSnapshot>>,
    inbound: crate::session::InboundMetadata,
}

type SelectionSnapshot = HashMap<usize, (Arc<GroupSelection>, usize)>;

impl EstablishContext {
    #[must_use]
    pub fn with_timeout(duration: Duration) -> Self {
        Self::with_resolution(duration, ResolutionContext::default())
    }

    #[must_use]
    pub fn with_resolution(duration: Duration, resolution: ResolutionContext) -> Self {
        Self {
            deadline: inherited_deadline(Instant::now() + duration),
            resolution,
            selections: Arc::new(Mutex::new(HashMap::new())),
            inbound: Default::default(),
        }
    }

    #[cfg(any(feature = "outbound-wireguard", feature = "outbound-masque"))]
    pub(crate) fn with_metadata(mut self, metadata: &crate::session::InboundMetadata) -> Self {
        self.inbound = metadata.clone();
        self
    }

    /// MASQUE's positive timeout owns shared creation independently of a
    /// waiting caller. Preserve its selected upstreams and inbound identity.
    #[cfg(feature = "outbound-masque")]
    pub(crate) fn masque_handshake(&self, seconds: i64) -> Self {
        // Go's time.Duration multiplication wraps at signed nanoseconds.
        let nanos = seconds.wrapping_mul(1_000_000_000);
        let now = Instant::now();
        Self {
            deadline: if nanos > 0 {
                now + Duration::from_nanos(nanos as u64)
            } else {
                now
            },
            resolution: self.resolution.clone(),
            selections: Arc::new(Mutex::new(
                self.selections
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            )),
            inbound: self.inbound.clone(),
        }
    }

    #[cfg(any(feature = "outbound-wireguard", feature = "outbound-hysteria2"))]
    pub(crate) fn capped_by(mut self, deadline: Instant) -> Self {
        self.deadline = self.deadline.min(inherited_deadline(deadline));
        self
    }

    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub async fn resolve_ip(
        &self,
        target: &Destination,
    ) -> Result<std::net::SocketAddr, DispatchError> {
        self.resolution.resolve_ip(target, self.deadline).await
    }

    pub fn resolution(&self) -> ResolutionContext {
        self.resolution.clone()
    }

    /// Only for a new physical path of an already authenticated session, never
    /// for extending an in-progress setup. Freeze its group choices and give
    /// this socket's complete upstream establishment a new absolute deadline.
    #[cfg(any(test, feature = "outbound-hysteria2", feature = "outbound-wireguard"))]
    pub(crate) fn authenticated_continuation(&self) -> Self {
        Self {
            deadline: Instant::now() + DEFAULT_ESTABLISH_TIMEOUT,
            resolution: self.resolution.clone(),
            inbound: self.inbound.clone(),
            selections: Arc::new(Mutex::new(
                self.selections
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            )),
        }
    }

    /// One read per group for the entire setup, including both legs of a
    /// SOCKS5 UDP association. Retaining the atomic prevents address reuse;
    /// unrelated groups are not an atomic cross-group snapshot.
    fn selected_member(&self, selection: &Arc<GroupSelection>, destination: &Destination) -> usize {
        selection.touch();
        let key = Arc::as_ptr(selection) as usize;
        let mut selections = self
            .selections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        selections
            .entry(key)
            .or_insert_with(|| {
                (
                    selection.clone(),
                    selection.choose_for(None, Some(destination), self.inbound.user.as_deref()),
                )
            })
            .1
    }

    fn report_group_outcome(&self, success: bool) {
        for (selection, _) in self.selections.lock().unwrap().values() {
            selection.outcome(success);
        }
    }

    pub async fn run<T, F>(&self, operation: &'static str, future: F) -> Result<T, DispatchError>
    where
        F: Future<Output = Result<T, DispatchError>>,
    {
        match timeout_at(self.deadline, future).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(error)) => {
                record_dispatch_diagnostic(operation, &error);
                Err(error)
            }
            Err(_) => {
                record_timeout_diagnostic(operation);
                tracing::warn!(operation, error_code = "timed_out", "outbound setup failed");
                Err(DispatchError::TimedOut)
            }
        }
    }

    pub async fn run_io<T, F>(&self, operation: &'static str, future: F) -> Result<T, DispatchError>
    where
        F: Future<Output = io::Result<T>>,
    {
        self.run(operation, async move {
            future.await.map_err(|error| {
                let diagnostic = record_io_diagnostic(operation, &error);
                tracing::warn!(
                    operation,
                    error_kind = ?error.kind(),
                    error = %diagnostic,
                    "outbound setup I/O failed"
                );
                DispatchError::from(error)
            })
        })
        .await
    }
}

impl Default for EstablishContext {
    fn default() -> Self {
        Self::with_timeout(DEFAULT_ESTABLISH_TIMEOUT)
    }
}

/// A connected stream plus the peer identity effective at the connector
/// boundary.
///
/// A direct connector reports the selected IP address. A proxy connector
/// reports the logical destination it asked the remote proxy to reach. SOCKS5
/// uses this distinction to normalize wildcard UDP relay replies without
/// performing DNS after TUN startup.
pub struct ConnectedStream {
    pub io: BoxStream,
    pub effective_peer: Destination,
}

impl std::fmt::Debug for ConnectedStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectedStream")
            .field("effective_peer", &self.effective_peer)
            .finish_non_exhaustive()
    }
}

/// Datagram setup parameters propagated through nested proxy layers.
///
/// `max_response_payload_size` is the largest wire payload accepted from the
/// connector being opened. An encapsulating connector, such as SOCKS5, widens
/// the value before opening its upstream and enforces the original value after
/// decoding its own header.
#[derive(Debug, Clone)]
pub struct DatagramRequest {
    pub session: DatagramSession,
    budget: crate::dispatch::DatagramBudget,
    udp_receive_buffer_size: Option<usize>,
    udp_send_buffer_size: Option<usize>,
    udp_dscp: Option<u8>,
}

impl DatagramRequest {
    #[must_use]
    pub fn new(session: DatagramSession) -> Self {
        let max_response_payload_size = session.max_response_payload_size();
        Self {
            session,
            budget: crate::dispatch::DatagramBudget::new(u16::MAX, max_response_payload_size),
            udp_receive_buffer_size: None,
            udp_send_buffer_size: None,
            udp_dscp: None,
        }
    }

    #[must_use]
    pub const fn max_response_payload_size(&self) -> u16 {
        self.budget.receive()
    }

    #[must_use]
    pub fn with_max_response_payload_size(&self, maximum: u16) -> Self {
        Self {
            session: self.session.clone(),
            budget: crate::dispatch::DatagramBudget::new(self.budget.transmit(), maximum),
            udp_receive_buffer_size: self.udp_receive_buffer_size,
            udp_send_buffer_size: self.udp_send_buffer_size,
            udp_dscp: self.udp_dscp,
        }
    }

    pub const fn budget(&self) -> crate::dispatch::DatagramBudget {
        self.budget
    }

    #[must_use]
    pub fn with_budget(&self, budget: crate::dispatch::DatagramBudget) -> Self {
        Self {
            session: self.session.clone(),
            budget,
            udp_receive_buffer_size: self.udp_receive_buffer_size,
            udp_send_buffer_size: self.udp_send_buffer_size,
            udp_dscp: self.udp_dscp,
        }
    }

    /// Best-effort hint for a locally owned physical UDP socket.
    /// This is independent of logical payload and receive credit limits.
    #[cfg(any(feature = "outbound-mieru", feature = "outbound-hysteria2"))]
    pub(crate) fn with_udp_receive_buffer_size(&self, size: usize) -> Self {
        let mut request = self.clone();
        request.udp_receive_buffer_size = Some(size);
        request
    }

    #[cfg(feature = "outbound-shadowsocks")]
    pub(crate) fn with_kcptun_socket(mut self, buffer: usize, dscp: u8) -> Self {
        self.udp_receive_buffer_size = Some(buffer);
        self.udp_send_buffer_size = Some(buffer);
        self.udp_dscp = (dscp > 0).then_some(dscp);
        self
    }
    pub(crate) fn udp_socket_options(&self) -> crate::dialer::UdpSocketOptions {
        crate::dialer::UdpSocketOptions {
            receive_buffer: self.udp_receive_buffer_size,
            send_buffer: self.udp_send_buffer_size,
            dscp: self.udp_dscp,
        }
    }
    /// Budget the wire envelope independently in each direction. A larger
    /// requested envelope can never increase a lower transport's real cap.
    pub fn with_envelope(&self, transmit: usize, receive: usize) -> Self {
        let widen = |value: u16, overhead: usize| {
            usize::from(value)
                .saturating_add(overhead)
                .min(usize::from(u16::MAX)) as u16
        };
        self.with_budget(crate::dispatch::DatagramBudget::new(
            widen(self.budget.transmit(), transmit),
            widen(self.budget.receive(), receive),
        ))
    }
}

/// Internal composable outbound boundary.
///
/// Unlike [`Dispatcher`], this boundary retains effective-peer metadata,
/// propagates one setup context through every hop, and lets encapsulating UDP
/// protocols adjust their upstream response budget.
#[async_trait]
pub trait OutboundConnector: Send + Sync {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError>;

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError>;

    /// Prevents new protocol-owned background work from being created.
    ///
    /// Most connectors are stateless and need no action. Session-multiplexed
    /// protocols override this hook so the runtime can begin a deterministic
    /// two-phase shutdown before waiting for inbound tasks.
    fn begin_shutdown(&self) {}

    /// Waits until protocol-owned background work has exited.
    async fn shutdown(&self) {}
}

/// A dependency-only select graph. It owns only its declared descendants,
/// never a registry of all nodes, so a validated DAG cannot form an Arc cycle.
/// The atomic is shared with the route/Controller view of the same group.
pub struct SelectUpstream {
    selection: Arc<GroupSelection>,
    members: Box<[SelectUpstreamMember]>,
    disable_udp: bool,
}

pub(crate) enum SelectUpstreamMember {
    Proxy(Arc<dyn OutboundConnector>),
    Group(Arc<SelectUpstream>),
    Direct,
    Reject,
    Control,
}

impl SelectUpstream {
    pub(crate) fn new(selection: Arc<GroupSelection>, members: Vec<SelectUpstreamMember>) -> Self {
        Self {
            selection,
            members: members.into_boxed_slice(),
            disable_udp: false,
        }
    }

    pub(crate) fn with_udp_disabled(mut self, disabled: bool) -> Self {
        self.disable_udp = disabled;
        self
    }
    fn check_udp(
        &self,
        context: &EstablishContext,
        destination: &Destination,
    ) -> Result<(), DispatchError> {
        let mut group = self;
        loop {
            if group.disable_udp {
                return Err(DispatchError::NotAllowed);
            }
            match group
                .members
                .get(context.selected_member(&group.selection, destination))
            {
                Some(SelectUpstreamMember::Group(next)) => group = next,
                Some(_) => return Ok(()),
                None => return Err(DispatchError::NotAllowed),
            }
        }
    }

    fn resolve(
        &self,
        context: &EstablishContext,
        destination: &Destination,
    ) -> Result<&SelectUpstreamMember, DispatchError> {
        let mut group = self;
        loop {
            let selected = context.selected_member(&group.selection, destination);
            match group.members.get(selected) {
                Some(SelectUpstreamMember::Group(next)) => group = next,
                Some(leaf) => return Ok(leaf),
                None => {
                    return Err(DispatchError::Other(
                        "invalid upstream group selection".to_owned(),
                    ));
                }
            }
        }
    }
}

enum ResolvedUpstream<'a> {
    Direct(&'a ResolvedEndpoint, &'a Dialer),
    LazyDirect(&'a Dialer),
    Proxy(&'a Arc<dyn OutboundConnector>),
}

/// The path used by one configured proxy to reach its own server.
#[derive(Clone)]
pub enum UpstreamPath {
    /// Physical endpoint resolution belongs to the current runtime DNS role.
    LazyDirect { dialer: Dialer },
    /// The physical first hop. Its endpoint was resolved during prepare.
    Direct {
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
    },
    /// Another configured proxy node. The target server remains a logical
    /// destination and is resolved by that proxy rather than by the host.
    Proxy(Arc<dyn OutboundConnector>),
    /// A runtime select group. DIRECT is relative to this node's prepared
    /// server, not the business destination or the ordinary routing engine.
    Group {
        server: Destination,
        group: Arc<SelectUpstream>,
        endpoint: Option<ResolvedEndpoint>,
        dialer: Dialer,
    },
}

impl std::fmt::Debug for UpstreamPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { endpoint, dialer } => formatter
                .debug_struct("DirectUpstream")
                .field("endpoint", endpoint)
                .field("dialer", dialer)
                .finish(),
            Self::LazyDirect { .. } => formatter.write_str("LazyDirectUpstream(..)"),
            Self::Proxy(_) => formatter.write_str("ProxyUpstream(..)"),
            Self::Group { .. } => formatter.write_str("GroupUpstream(..)"),
        }
    }
}

impl UpstreamPath {
    /// A multi-endpoint node shares the declared graph, while each
    /// physical peer has its own server and may refresh a previously pinned IP.
    #[cfg(any(
        feature = "outbound-wireguard",
        feature = "outbound-mieru",
        feature = "outbound-hysteria2"
    ))]
    pub(crate) fn for_server(&self, server: &Destination, refresh: bool) -> Self {
        match self {
            Self::Direct { endpoint, dialer }
                if refresh || validate_prepared_endpoint(server, endpoint).is_err() =>
            {
                Self::LazyDirect {
                    dialer: dialer.clone(),
                }
            }
            Self::Group {
                server: original,
                group,
                endpoint,
                dialer,
            } => Self::Group {
                server: server.clone(),
                group: group.clone(),
                endpoint: if refresh || original != server {
                    None
                } else {
                    endpoint.clone()
                },
                dialer: dialer.clone(),
            },
            _ => self.clone(),
        }
    }

    #[must_use]
    pub const fn direct(endpoint: ResolvedEndpoint, dialer: Dialer) -> Self {
        Self::Direct { endpoint, dialer }
    }

    #[must_use]
    pub fn proxy(connector: Arc<dyn OutboundConnector>) -> Self {
        Self::Proxy(connector)
    }

    pub(crate) fn is_direct(&self, context: &EstablishContext) -> Result<bool, DispatchError> {
        Ok(matches!(
            self.resolve(context)?,
            ResolvedUpstream::Direct(..) | ResolvedUpstream::LazyDirect(..)
        ))
    }

    fn resolve(&self, context: &EstablishContext) -> Result<ResolvedUpstream<'_>, DispatchError> {
        match self {
            Self::Direct { endpoint, dialer } => Ok(ResolvedUpstream::Direct(endpoint, dialer)),
            Self::LazyDirect { dialer } => Ok(ResolvedUpstream::LazyDirect(dialer)),
            Self::Proxy(connector) => Ok(ResolvedUpstream::Proxy(connector)),
            Self::Group {
                group,
                endpoint,
                dialer,
                server,
            } => match group.resolve(context, server)? {
                SelectUpstreamMember::Proxy(connector) => Ok(ResolvedUpstream::Proxy(connector)),
                SelectUpstreamMember::Direct => endpoint
                    .as_ref()
                    .map(|endpoint| ResolvedUpstream::Direct(endpoint, dialer))
                    .map_or_else(|| Ok(ResolvedUpstream::LazyDirect(dialer)), Ok),
                SelectUpstreamMember::Reject | SelectUpstreamMember::Control => {
                    Err(DispatchError::NotAllowed)
                }
                SelectUpstreamMember::Group(_) => {
                    unreachable!("upstream resolution returns a leaf")
                }
            },
        }
    }

    pub async fn connect_server(
        &self,
        mut session: StreamSession,
        server: &Destination,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        session.destination = server.clone();
        match self.resolve(context)? {
            ResolvedUpstream::Direct(endpoint, dialer) => {
                validate_prepared_endpoint(server, endpoint)?;
                let stream = context
                    .run_io("physical proxy-server connect", dialer.connect(endpoint))
                    .await?;
                let effective_peer =
                    Destination::Ip(stream.peer_addr().map_err(DispatchError::from)?);
                Ok(ConnectedStream {
                    io: Box::new(stream),
                    effective_peer,
                })
            }
            ResolvedUpstream::LazyDirect(dialer) => {
                let endpoint = context
                    .resolution
                    .clone()
                    .with_ip_version(dialer.ip_version())
                    .resolve_proxy(server, context.deadline)
                    .await?;
                let stream = context
                    .run_io("physical proxy-server connect", dialer.connect(&endpoint))
                    .await?;
                let effective_peer =
                    Destination::Ip(stream.peer_addr().map_err(DispatchError::from)?);
                Ok(ConnectedStream {
                    io: Box::new(stream),
                    effective_peer,
                })
            }
            ResolvedUpstream::Proxy(connector) => connector.connect_stream(session, context).await,
        }
    }

    pub async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if let Self::Group { group, server, .. } = self {
            group.check_udp(context, server)?;
        }
        match self.resolve(context)? {
            ResolvedUpstream::Direct(_, dialer) | ResolvedUpstream::LazyDirect(dialer) => {
                let direct = DirectOutbound::new(dialer.clone());
                OutboundConnector::open_datagram(&direct, request, context).await
            }
            ResolvedUpstream::Proxy(connector) => connector.open_datagram(request, context).await,
        }
    }

    /// Pins a native UDP server using the node resolver when first needed.
    /// Resolving here and opening IO below share the context's group snapshot.
    #[cfg(any(
        feature = "outbound-vmess",
        feature = "outbound-shadowsocks",
        feature = "outbound-vless",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "outbound-trusttunnel",
        feature = "outbound-mieru",
        feature = "outbound-masque",
        feature = "outbound-wireguard"
    ))]
    pub(crate) async fn datagram_server(
        &self,
        server: &Destination,
        context: &EstablishContext,
    ) -> Result<Destination, DispatchError> {
        match self.resolve(context)? {
            ResolvedUpstream::Direct(endpoint, dialer) => {
                validate_prepared_endpoint(server, endpoint)?;
                dialer
                    .ordered_addresses(&endpoint.addresses)
                    .first()
                    .copied()
                    .map(Destination::Ip)
                    .ok_or(DispatchError::HostUnreachable)
            }
            ResolvedUpstream::LazyDirect(dialer) => context
                .resolution
                .clone()
                .with_ip_version(dialer.ip_version())
                .resolve_proxy(server, context.deadline)
                .await?
                .addresses
                .first()
                .copied()
                .map(Destination::Ip)
                .ok_or(DispatchError::HostUnreachable),
            ResolvedUpstream::Proxy(_) => Ok(server.clone()),
        }
    }
}

pub(crate) struct IpVersionConnector {
    pub inner: Arc<dyn OutboundConnector>,
    pub version: crate::config::IpVersion,
}
#[async_trait]
impl OutboundConnector for IpVersionConnector {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let mut context = context.clone();
        context.resolution = context.resolution.with_ip_version(self.version);
        self.inner.connect_stream(session, &context).await
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let mut context = context.clone();
        context.resolution = context.resolution.with_ip_version(self.version);
        self.inner.open_datagram(request, &context).await
    }
    fn begin_shutdown(&self) {
        self.inner.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// Creates the logical server destination retained by proxy connectors.
pub fn server_destination(address: &str, port: u16) -> io::Result<Destination> {
    if let Ok(address) = address.parse::<IpAddr>() {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy server port is zero",
            ));
        }
        Ok(Destination::Ip(std::net::SocketAddr::new(address, port)))
    } else {
        Destination::domain(address, port)
    }
}

fn validate_prepared_endpoint(
    server: &Destination,
    endpoint: &ResolvedEndpoint,
) -> Result<(), DispatchError> {
    if server.port() != endpoint.port || endpoint.addresses.is_empty() {
        return Err(DispatchError::Other(
            "prepared endpoint does not match the configured proxy server".to_owned(),
        ));
    }
    let matches = match server {
        Destination::Domain { host, .. } => host == &endpoint.logical_host,
        Destination::Ip(address) => {
            endpoint.logical_host.parse::<IpAddr>().ok() == Some(address.ip())
                && endpoint.addresses.iter().any(|item| item == address)
        }
    };
    if !matches {
        return Err(DispatchError::Other(
            "prepared endpoint does not match the configured proxy server".to_owned(),
        ));
    }
    Ok(())
}

/// Adapts a connector back to the stable inbound/router dispatcher boundary.
pub struct ConnectorDispatcher {
    inner: Arc<dyn OutboundConnector>,
    allow_udp: bool,
    resolution: ResolutionContext,
}

impl ConnectorDispatcher {
    #[must_use]
    pub fn new(inner: Arc<dyn OutboundConnector>) -> Self {
        Self {
            inner,
            allow_udp: true,
            resolution: ResolutionContext::default(),
        }
    }

    /// Creates the routed boundary for one configured proxy.
    ///
    /// The capability applies only when rules select this node directly.
    /// Internal `dialer-proxy` hops keep using the raw connector so a parent
    /// carrying a child TCP stream is not rejected by the parent's UDP flag.
    #[must_use]
    pub fn with_udp_capability(inner: Arc<dyn OutboundConnector>, allow_udp: bool) -> Self {
        Self {
            inner,
            allow_udp,
            resolution: ResolutionContext::default(),
        }
    }

    #[must_use]
    pub fn with_resolution(mut self, resolution: ResolutionContext) -> Self {
        self.resolution = resolution;
        self
    }

    fn context(&self, metadata: &crate::session::InboundMetadata) -> EstablishContext {
        let mut context =
            EstablishContext::with_resolution(DEFAULT_ESTABLISH_TIMEOUT, self.resolution.clone());
        context.inbound = metadata.clone();
        context
    }
}

#[async_trait]
impl Dispatcher for ConnectorDispatcher {
    fn supports_udp(&self) -> bool {
        self.allow_udp
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let context = self.context(&session.metadata);
        let result = self.inner.connect_stream(session, &context).await;
        if !matches!(result, Err(DispatchError::NotAllowed)) {
            context.report_group_outcome(result.is_ok());
        }
        result.map(|connected| connected.io)
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if !self.allow_udp {
            return Err(DispatchError::NotAllowed);
        }
        let context = self.context(&session.metadata);
        self.inner
            .open_datagram(DatagramRequest::new(session), &context)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::session::{Datagram, InboundKind};
    use bytes::Bytes;
    use std::future::pending;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::Semaphore,
    };

    use super::*;

    #[cfg(feature = "outbound-hysteria2")]
    #[tokio::test]
    async fn authenticated_continuation_keeps_group_choice_but_has_a_new_io_deadline() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "HYSTERIA2-UNIT",
            "authenticated_continuation_keeps_group_choice_but_has_a_new_io_deadline",
        );
        let selection = Arc::new(GroupSelection::new(0));
        let path = selected_path(
            selection.clone(),
            vec![
                SelectUpstreamMember::Proxy(Arc::new(MarkedConnector {
                    marker: 1,
                    ..Default::default()
                })),
                SelectUpstreamMember::Proxy(Arc::new(MarkedConnector {
                    marker: 2,
                    ..Default::default()
                })),
            ],
        );
        let context = EstablishContext::with_timeout(Duration::from_millis(1));
        let request = DatagramRequest::new(DatagramSession::new(
            InboundKind::InternalMeasure,
            test_session().source,
        ));
        let mut initial = path.open_datagram(request.clone(), &context).await.unwrap();
        assert_eq!(initial.receive().await.unwrap().payload[0], 1);
        tokio::time::sleep(Duration::from_millis(2)).await;
        selection.store(1, Ordering::Release);
        let continuation = context.authenticated_continuation();
        assert!(context.deadline() < Instant::now());
        assert!(continuation.deadline() > Instant::now());
        let mut old = path
            .open_datagram(request.clone(), &continuation)
            .await
            .unwrap();
        assert_eq!(old.receive().await.unwrap().payload[0], 1);
        let mut new = path
            .open_datagram(request, &EstablishContext::default())
            .await
            .unwrap();
        assert_eq!(new.receive().await.unwrap().payload[0], 2);
    }

    struct UnreachableConnector;

    #[derive(Default)]
    struct MarkedConnector {
        marker: u8,
        calls: Mutex<Vec<(Destination, Instant)>>,
        budgets: Mutex<Vec<u16>>,
        sends: Arc<AtomicUsize>,
        gate: Option<Arc<Semaphore>>,
        reject_udp: bool,
    }

    #[async_trait]
    impl OutboundConnector for MarkedConnector {
        async fn connect_stream(
            &self,
            session: StreamSession,
            context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            self.calls
                .lock()
                .unwrap()
                .push((session.destination.clone(), context.deadline()));
            if let Some(gate) = &self.gate {
                context
                    .run("test gated upstream", async {
                        gate.acquire().await.unwrap().forget();
                        Ok(())
                    })
                    .await?;
            }
            let (client, mut peer) = tokio::io::duplex(16);
            peer.write_all(&[self.marker; 2]).await.unwrap();
            Ok(ConnectedStream {
                io: Box::new(client),
                effective_peer: session.destination,
            })
        }

        async fn open_datagram(
            &self,
            request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.budgets
                .lock()
                .unwrap()
                .push(request.max_response_payload_size());
            if self.reject_udp {
                return Err(DispatchError::NotAllowed);
            }
            Ok(Box::new(MarkedDatagrams {
                marker: self.marker,
                sends: self.sends.clone(),
            }))
        }
    }

    struct MarkedDatagrams {
        marker: u8,
        sends: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DatagramTransport for MarkedDatagrams {
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            Ok(Datagram {
                remote: test_session().destination,
                payload: Bytes::from(vec![self.marker]),
                sniffed_domain: None,
            })
        }
    }

    fn test_session() -> StreamSession {
        StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Http,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::domain("business.invalid", 443).unwrap(),
            sniffed_domain: None,
        }
    }

    fn test_request() -> DatagramRequest {
        DatagramRequest::new(DatagramSession::new(
            InboundKind::Tun,
            test_session().source,
        ))
        .with_max_response_payload_size(1714)
    }

    fn selected_path(
        selection: Arc<GroupSelection>,
        members: Vec<SelectUpstreamMember>,
    ) -> UpstreamPath {
        UpstreamPath::Group {
            server: Destination::domain("server.example", 443).unwrap(),
            group: Arc::new(SelectUpstream::new(selection, members)),
            endpoint: None,
            dialer: Dialer::default(),
        }
    }

    #[tokio::test]
    async fn ingress_connector_dispatcher_preserves_user_for_dialer_proxy_and_continuations() {
        struct Carrier {
            path: UpstreamPath,
            user: Arc<str>,
        }
        #[async_trait]
        impl OutboundConnector for Carrier {
            async fn connect_stream(
                &self,
                session: StreamSession,
                context: &EstablishContext,
            ) -> Result<ConnectedStream, DispatchError> {
                assert_eq!(context.inbound.user.as_deref(), Some(self.user.as_ref()));
                assert_eq!(session.metadata, context.inbound);
                self.path
                    .connect_server(
                        session,
                        &Destination::domain("server.example", 443).unwrap(),
                        context,
                    )
                    .await
            }
            async fn open_datagram(
                &self,
                request: DatagramRequest,
                context: &EstablishContext,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                assert_eq!(context.inbound, request.session.metadata);
                let continuation = context.authenticated_continuation();
                assert_eq!(continuation.inbound, context.inbound);
                self.path.open_datagram(request, &continuation).await
            }
        }
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.10, port: 1080, udp: true}
  - {name: b, type: socks5, server: 192.0.2.11, port: 1080, udp: true}
proxy-groups:
  - {name: balance, type: load-balance, proxies: [a,b], hash-key: in-user}
"#,
        )
        .unwrap();
        let selection = Arc::new(GroupSelection::new(0));
        selection.configure_balance(&config.proxy_groups[0]);
        let server = Destination::domain("server.example", 443).unwrap();
        let fallback = selection.choose_for(None, Some(&server), None);
        let user: Arc<str> = Arc::from(
            (0..256)
                .map(|i| format!("verified-{i}"))
                .find(|user| selection.choose_for(None, Some(&server), Some(user)) != fallback)
                .unwrap(),
        );
        let expected = selection.choose_for(None, Some(&server), Some(&user)) as u8 + 1;
        let path = selected_path(
            selection,
            vec![
                SelectUpstreamMember::Proxy(Arc::new(MarkedConnector {
                    marker: 1,
                    ..Default::default()
                })),
                SelectUpstreamMember::Proxy(Arc::new(MarkedConnector {
                    marker: 2,
                    ..Default::default()
                })),
            ],
        );
        let dispatcher = ConnectorDispatcher::new(Arc::new(Carrier {
            path,
            user: user.clone(),
        }));
        let metadata = crate::session::InboundMetadata {
            local_port: 1080,
            user: Some(user),
            ..Default::default()
        };
        let mut session = test_session();
        session.metadata = metadata.clone();
        let mut stream = dispatcher.connect_tcp(session).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), expected);
        let mut udp = dispatcher
            .open_datagram(
                DatagramSession::new(InboundKind::Socks5, test_session().source)
                    .with_metadata(metadata),
            )
            .await
            .unwrap();
        assert_eq!(udp.receive().await.unwrap().payload[0], expected);
    }

    #[tokio::test]
    async fn group_upstream_pins_nested_choices_and_preserves_metadata_budget_and_deadline() {
        let first = Arc::new(MarkedConnector {
            marker: 1,
            ..Default::default()
        });
        let second = Arc::new(MarkedConnector {
            marker: 2,
            ..Default::default()
        });
        let selection = Arc::new(GroupSelection::new(0));
        let nested = Arc::new(SelectUpstream::new(
            selection.clone(),
            vec![
                SelectUpstreamMember::Proxy(first.clone()),
                SelectUpstreamMember::Proxy(second.clone()),
            ],
        ));
        let outer_selection = Arc::new(GroupSelection::new(0));
        let path = selected_path(
            outer_selection.clone(),
            vec![
                SelectUpstreamMember::Group(nested),
                SelectUpstreamMember::Reject,
            ],
        );
        let context = EstablishContext::with_timeout(Duration::from_secs(1));
        let server = Destination::domain("proxy.invalid", 1080).unwrap();
        let mut stream = path
            .connect_server(test_session(), &server, &context)
            .await
            .unwrap();
        assert_eq!(stream.effective_peer, server);
        assert_eq!(*first.calls.lock().unwrap(), [(server, context.deadline())]);

        selection.store(1, Ordering::Release);
        outer_selection.store(1, Ordering::Release);
        // The same setup cannot re-read either group between control and data.
        let mut old_udp = path.open_datagram(test_request(), &context).await.unwrap();
        assert_eq!(old_udp.receive().await.unwrap().payload.as_ref(), &[1]);
        assert_eq!(*first.budgets.lock().unwrap(), [1714]);
        assert!(matches!(
            path.open_datagram(test_request(), &EstablishContext::default())
                .await,
            Err(DispatchError::NotAllowed)
        ));

        outer_selection.store(0, Ordering::Release);
        let mut new_udp = path
            .open_datagram(test_request(), &EstablishContext::default())
            .await
            .unwrap();
        assert_eq!(new_udp.receive().await.unwrap().payload.as_ref(), &[2]);
        assert_eq!(*second.budgets.lock().unwrap(), [1714]);
        assert_eq!(stream.io.read_u8().await.unwrap(), 1);
        old_udp
            .send(Datagram {
                remote: test_session().destination,
                payload: Bytes::from_static(b"old"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(first.sends.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn group_change_during_connect_keeps_old_path_and_does_not_reset_deadline() {
        let gate = Arc::new(Semaphore::new(0));
        let old = Arc::new(MarkedConnector {
            marker: 1,
            gate: Some(gate.clone()),
            ..Default::default()
        });
        let new = Arc::new(MarkedConnector {
            marker: 2,
            ..Default::default()
        });
        let selection = Arc::new(GroupSelection::new(0));
        let path = selected_path(
            selection.clone(),
            vec![
                SelectUpstreamMember::Proxy(old.clone()),
                SelectUpstreamMember::Proxy(new.clone()),
            ],
        );
        let server = Destination::domain("proxy.invalid", 1080).unwrap();
        let context = EstablishContext::default();
        let mut connecting = Box::pin(path.connect_server(test_session(), &server, &context));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut connecting)
                .await
                .is_err()
        );
        assert_eq!(old.calls.lock().unwrap().len(), 1);
        selection.store(1, Ordering::Release);
        gate.add_permits(1);
        assert_eq!(connecting.await.unwrap().io.read_u8().await.unwrap(), 1);
        assert_eq!(
            path.connect_server(test_session(), &server, &EstablishContext::default())
                .await
                .unwrap()
                .io
                .read_u8()
                .await
                .unwrap(),
            2
        );

        selection.store(0, Ordering::Release);
        let context = EstablishContext::with_timeout(Duration::from_millis(10));
        assert!(matches!(
            path.connect_server(test_session(), &server, &context).await,
            Err(DispatchError::TimedOut)
        ));
        assert_eq!(
            old.calls.lock().unwrap().last().unwrap().1,
            context.deadline()
        );
    }

    #[tokio::test]
    async fn cancelled_group_setup_releases_connector_and_selection_snapshot() {
        let connector = Arc::new(MarkedConnector {
            gate: Some(Arc::new(Semaphore::new(0))),
            ..Default::default()
        });
        let selection = Arc::new(GroupSelection::new(0));
        let connector_weak = Arc::downgrade(&connector);
        let selection_weak = Arc::downgrade(&selection);
        let path = selected_path(selection, vec![SelectUpstreamMember::Proxy(connector)]);
        let server = Destination::domain("proxy.invalid", 1080).unwrap();
        let context = EstablishContext::default();
        let mut connecting = Box::pin(path.connect_server(test_session(), &server, &context));
        assert!(futures_util::poll!(&mut connecting).is_pending());
        drop(connecting);
        drop(path);
        assert!(connector_weak.upgrade().is_none());
        assert!(selection_weak.upgrade().is_some());
        drop(context);
        assert!(selection_weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn upstream_direct_connects_prepared_node_server_and_reject_never_falls_back() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let selection = Arc::new(GroupSelection::new(0));
        let path = UpstreamPath::Group {
            server: Destination::domain("server.example", 443).unwrap(),
            group: Arc::new(SelectUpstream::new(
                selection.clone(),
                vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
            )),
            endpoint: Some(ResolvedEndpoint {
                logical_host: "127.0.0.1".to_owned(),
                port: address.port(),
                addresses: vec![address],
            }),
            dialer: Dialer::default(),
        };
        let server = Destination::Ip(address);
        let context = EstablishContext::default();
        let stream = path
            .connect_server(test_session(), &server, &context)
            .await
            .unwrap();
        assert_eq!(stream.effective_peer, server);
        assert!(path.is_direct(&context).unwrap());
        let (_peer, _) = listener.accept().await.unwrap();
        selection.store(1, Ordering::Release);
        assert!(matches!(
            path.connect_server(test_session(), &server, &EstablishContext::default())
                .await,
            Err(DispatchError::NotAllowed)
        ));
        assert!(matches!(
            path.open_datagram(test_request(), &EstablishContext::default())
                .await,
            Err(DispatchError::NotAllowed)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
        selection.store(0, Ordering::Release);
        assert!(
            path.connect_server(
                test_session(),
                &test_session().destination,
                &EstablishContext::default()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn group_direct_uses_the_protected_socket_seam_and_fails_closed() {
        struct RejectProtector(AtomicUsize);
        impl crate::dialer::SocketProtector for RejectProtector {
            fn protect(&self, _socket: i32) -> io::Result<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture protect denial",
                ))
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let protector = Arc::new(RejectProtector(AtomicUsize::new(0)));
        let path = UpstreamPath::Group {
            server: Destination::domain("server.example", 443).unwrap(),
            group: Arc::new(SelectUpstream::new(
                Arc::new(GroupSelection::new(0)),
                vec![SelectUpstreamMember::Direct],
            )),
            endpoint: Some(ResolvedEndpoint {
                logical_host: "127.0.0.1".into(),
                port: address.port(),
                addresses: vec![address],
            }),
            dialer: Dialer::default().with_protector(protector.clone()),
        };
        assert!(matches!(
            path.connect_server(
                test_session(),
                &Destination::Ip(address),
                &EstablishContext::default()
            )
            .await,
            Err(DispatchError::NotAllowed)
        ));
        assert_eq!(protector.0.load(Ordering::Relaxed), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn dynamic_udp_capability_affects_only_new_associations() {
        let enabled = Arc::new(MarkedConnector {
            marker: 1,
            ..Default::default()
        });
        let disabled = Arc::new(MarkedConnector {
            reject_udp: true,
            ..Default::default()
        });
        let selection = Arc::new(GroupSelection::new(0));
        let path = selected_path(
            selection.clone(),
            vec![
                SelectUpstreamMember::Proxy(enabled.clone()),
                SelectUpstreamMember::Proxy(disabled.clone()),
            ],
        );
        let mut old = path
            .open_datagram(test_request(), &EstablishContext::default())
            .await
            .unwrap();
        selection.store(1, Ordering::Release);
        assert!(matches!(
            path.open_datagram(test_request(), &EstablishContext::default())
                .await,
            Err(DispatchError::NotAllowed)
        ));
        assert_eq!(old.receive().await.unwrap().payload.as_ref(), &[1]);
        assert!(
            path.connect_server(
                test_session(),
                &test_session().destination,
                &EstablishContext::default()
            )
            .await
            .is_ok()
        );
        // Concrete and grouped upstreams expose the same actual transport capability.
        assert!(matches!(
            UpstreamPath::proxy(disabled)
                .open_datagram(test_request(), &EstablishContext::default())
                .await,
            Err(DispatchError::NotAllowed)
        ));
    }

    #[async_trait]
    impl OutboundConnector for UnreachableConnector {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            unreachable!()
        }

        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            unreachable!()
        }
    }

    #[test]
    fn server_destination_keeps_domains_and_literals_distinct() {
        assert!(matches!(
            server_destination("example.com", 443).unwrap(),
            Destination::Domain { .. }
        ));
        assert!(matches!(
            server_destination("2001:db8::1", 443).unwrap(),
            Destination::Ip(_)
        ));
        assert!(server_destination("example.com", 0).is_err());
    }

    #[test]
    fn nested_datagram_budget_is_explicit_and_saturating_at_callers() {
        let session = DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        );
        let request = DatagramRequest::new(session);
        assert_eq!(request.udp_socket_options().receive_buffer, None);
        #[cfg(any(feature = "outbound-mieru", feature = "outbound-hysteria2"))]
        {
            let request = request.with_udp_receive_buffer_size(512 * 1024);
            for adjusted in [
                request.with_budget(crate::dispatch::DatagramBudget::new(1_200, 1_400)),
                request.with_max_response_payload_size(1_714),
                request.with_envelope(32, 64),
            ] {
                assert_eq!(
                    adjusted.udp_socket_options().receive_buffer,
                    Some(512 * 1024)
                );
            }
        }
        assert_eq!(request.max_response_payload_size(), 1_452);
        assert_eq!(
            request
                .with_max_response_payload_size(1_714)
                .max_response_payload_size(),
            1_714
        );
    }

    #[tokio::test]
    async fn establish_deadline_remains_a_typed_timeout() {
        let result = EstablishContext::with_timeout(Duration::ZERO)
            .run("test operation", pending::<Result<(), DispatchError>>())
            .await;
        assert!(matches!(result, Err(DispatchError::TimedOut)));
    }

    #[tokio::test]
    async fn routed_udp_capability_does_not_open_the_raw_connector() {
        let dispatcher =
            ConnectorDispatcher::with_udp_capability(Arc::new(UnreachableConnector), false);
        let session = DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        );

        assert!(matches!(
            dispatcher.open_datagram(session).await,
            Err(DispatchError::NotAllowed)
        ));
    }

    #[tokio::test]
    async fn diagnostic_capture_keeps_the_first_stage_and_bounds_utf8_error_text() {
        let context = EstablishContext::default();
        let raw = format!("握手失败\r\nInjected: yes {}", "界".repeat(100));
        let (result, diagnostic) = capture_outbound_diagnostic(context.run(
            "physical proxy-server connect",
            context.run_io("VLESS TLS/REALITY handshake", async move {
                Err::<(), _>(io::Error::new(io::ErrorKind::InvalidData, raw))
            }),
        ))
        .await;

        assert!(matches!(result, Err(DispatchError::Other(_))));
        let diagnostic = diagnostic.unwrap();
        assert_eq!(diagnostic.stage(), "vless-security");
        assert_eq!(diagnostic.kind(), "invalid_data");
        assert!(
            diagnostic
                .message()
                .starts_with("握手失败\r\nInjected: yes ")
        );
        assert!(diagnostic.message().ends_with("..."));
        assert!(diagnostic.message().len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES);
        assert!(std::str::from_utf8(diagnostic.message().as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn diagnostic_capture_preserves_timeout_status_and_stage() {
        let context = EstablishContext::with_timeout(Duration::ZERO);
        let (result, diagnostic) = capture_outbound_diagnostic(context.run(
            "physical proxy-server connect",
            pending::<Result<(), DispatchError>>(),
        ))
        .await;

        assert!(matches!(result, Err(DispatchError::TimedOut)));
        let diagnostic = diagnostic.unwrap();
        assert_eq!(diagnostic.stage(), "physical-connect");
        assert_eq!(diagnostic.kind(), "timed_out");
        assert_eq!(diagnostic.message(), "outbound setup deadline expired");
    }
}
