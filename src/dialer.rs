use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(all(windows, feature = "windows-uwp"))]
use std::{
    num::NonZeroU32,
    os::windows::io::{AsRawSocket, RawSocket},
};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpSocket, UdpSocket},
    sync::{Notify, Semaphore},
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[cfg(all(windows, feature = "windows-uwp"))]
use windows::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR,
    WSAGetLastError, setsockopt,
};

use crate::limits::{DNS_WORKER_STACK_BYTES, MAX_DNS_WORKERS, MAX_SOCKET_INITIALIZATIONS};
use crate::resources::observation::{ObservedIo, ResourceKind, track};

pub type PhysicalStream = ObservedIo<tokio::net::TcpStream>;
pub type PhysicalDatagram = ObservedIo<UdpSocket>;

const MAX_RESOLVED_ADDRESSES: usize = 8;

static DNS_WORKER_POOL: OnceLock<DnsWorkerPool> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub logical_host: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
}

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

#[derive(Debug)]
struct DnsWorker {
    requests: SyncSender<DnsRequest>,
    busy: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DnsWorkerPool {
    workers: Mutex<Vec<DnsWorker>>,
    available: Arc<Notify>,
}

#[derive(Debug)]
struct DnsWorkerLease {
    requests: SyncSender<DnsRequest>,
    busy: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DnsRequest {
    host: String,
    port: u16,
    response: tokio::sync::oneshot::Sender<io::Result<Vec<SocketAddr>>>,
}

impl DnsWorker {
    fn spawn(slot: usize, available: Arc<Notify>) -> io::Result<Self> {
        let (requests, receiver) = sync_channel::<DnsRequest>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = busy.clone();
        thread::Builder::new()
            .name(format!("vole-bootstrap-dns-{slot}"))
            .stack_size(DNS_WORKER_STACK_BYTES)
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let result = std::panic::catch_unwind(|| {
                        (request.host.as_str(), request.port)
                            .to_socket_addrs()
                            .map(take_resolved_addresses)
                    })
                    .unwrap_or_else(|_| Err(io::Error::other("bootstrap DNS worker panicked")));
                    worker_busy.store(false, Ordering::Release);
                    available.notify_one();
                    let _ = request.response.send(result);
                }
            })?;
        Ok(Self { requests, busy })
    }

    fn try_claim(&self) -> Option<DnsWorkerLease> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }

        Some(DnsWorkerLease {
            requests: self.requests.clone(),
            busy: self.busy.clone(),
        })
    }
}

impl DnsWorkerPool {
    async fn claim_worker(&self) -> io::Result<DnsWorkerLease> {
        loop {
            // Register before inspecting worker state so a completion between
            // the scan and await cannot be lost.
            let notified = self.available.notified();
            {
                let mut workers = self
                    .workers
                    .lock()
                    .map_err(|_| io::Error::other("bootstrap DNS worker pool lock is poisoned"))?;

                // Always scan from slot zero so sequential lookups reuse the
                // first worker. A new thread is created only when every
                // existing slot is still occupied by getaddrinfo.
                if let Some(lease) = workers.iter().find_map(DnsWorker::try_claim) {
                    return Ok(lease);
                }
                if workers.len() < MAX_DNS_WORKERS {
                    let worker = DnsWorker::spawn(workers.len(), Arc::clone(&self.available))?;
                    let lease = worker.try_claim().ok_or_else(|| {
                        io::Error::other("new bootstrap DNS worker is unexpectedly busy")
                    })?;
                    workers.push(worker);
                    return Ok(lease);
                }
            }
            notified.await;
        }
    }

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let worker = self.claim_worker().await?;

        let (response, receiver) = tokio::sync::oneshot::channel();
        if worker
            .requests
            .try_send(DnsRequest {
                host: host.to_owned(),
                port,
                response,
            })
            .is_err()
        {
            worker.busy.store(false, Ordering::Release);
            self.available.notify_one();
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "bootstrap DNS worker is unavailable",
            ));
        }
        receiver.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "bootstrap DNS worker stopped before replying",
            )
        })?
    }

    #[cfg(test)]
    fn worker_count(&self) -> usize {
        self.workers.lock().unwrap().len()
    }
}

impl Default for DnsWorkerPool {
    fn default() -> Self {
        Self {
            workers: Mutex::new(Vec::new()),
            available: Arc::new(Notify::new()),
        }
    }
}

fn take_resolved_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addresses.into_iter().take(MAX_RESOLVED_ADDRESSES).collect()
}

fn dns_worker_pool() -> &'static DnsWorkerPool {
    DNS_WORKER_POOL.get_or_init(DnsWorkerPool::default)
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server port is zero",
            ));
        }
        let mut addresses = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            let addresses = dns_worker_pool().resolve(host, port).await?;
            if addresses.iter().any(|address| address.ip().is_loopback()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy server hostname resolved to a loopback address",
                ));
            }
            addresses
        };
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "server did not resolve to an address",
            ));
        }
        Ok(ResolvedEndpoint {
            logical_host: host.to_owned(),
            port,
            addresses,
        })
    }
}

/// Platform hook invoked after socket creation and before connect.
pub trait SocketProtector: Send + Sync {
    fn protect(&self, socket: i32) -> io::Result<()>;
}

/// Owns synchronous socket setup independently of the async I/O workers.
/// A started syscall cannot be aborted; shutdown must wait for its result to
/// be delivered or destroyed before releasing any platform callback lease.
#[derive(Debug)]
struct SocketInitialization {
    closed: Mutex<bool>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    submissions: Arc<Semaphore>,
}

impl Default for SocketInitialization {
    fn default() -> Self {
        Self {
            closed: Mutex::new(false),
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
            submissions: Arc::new(Semaphore::new(MAX_SOCKET_INITIALIZATIONS)),
        }
    }
}

impl SocketInitialization {
    async fn run<T, F>(&self, operation: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn Fn() -> io::Result<()>) -> io::Result<T> + Send + 'static,
    {
        // Await before registration/submission. Dropping the caller future
        // cancels this wait; scope shutdown also wakes every waiting caller.
        let permit = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(socket_initialization_cancelled()),
            permit = Arc::clone(&self.submissions).acquire_owned() => {
                permit.map_err(|_| socket_initialization_cancelled())?
            }
        };
        let (response, receiver) = tokio::sync::oneshot::channel();
        let token = {
            let closed = self
                .closed
                .lock()
                .map_err(|_| io::Error::other("socket initialization lock is poisoned"))?;
            if *closed {
                return Err(socket_initialization_cancelled());
            }
            // close() alone does not prohibit TaskTracker from admitting tasks.
            // Register while holding the same short lock as begin_shutdown().
            self.tasks.token()
        };
        let cancellation = self.cancellation.clone();
        let guard = track(ResourceKind::Task);
        let task =
            tokio::task::spawn_blocking(crate::resources::observation::inherit_thread(move || {
                // Return capacity only after the tracking guard/token. A
                // cancelled receiver must not release a started job's permit.
                let _permit = permit;
                let _token = token;
                let _guard = guard;
                let check = || {
                    if cancellation.is_cancelled() || response.is_closed() {
                        Err(socket_initialization_cancelled())
                    } else {
                        Ok(())
                    }
                };
                let result = check().and_then(|()| operation(&check));
                // Do not return a socket as the blocking task's output: Tokio
                // could retain it after our tracking token has been released.
                // A cancelled receiver destroys the result inside this scope.
                drop(response.send(result));
            }));
        let _abort = tokio_util::task::AbortOnDropHandle::new(task);
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(socket_initialization_cancelled()),
            result = receiver => result.map_err(|_| io::Error::other("socket initialization task failed"))?,
        }
    }

    fn begin_shutdown(&self) {
        let mut closed = self
            .closed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *closed = true;
        self.cancellation.cancel();
        self.submissions.close();
        self.tasks.close();
    }

    async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
    }
}

fn socket_initialization_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "socket initialization cancelled",
    )
}

#[derive(Debug, Clone, Copy)]
struct SourceBinding {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

#[cfg(all(windows, feature = "windows-uwp"))]
#[derive(Debug, Clone, Copy)]
struct InterfaceBinding {
    ipv4: Option<(Ipv4Addr, NonZeroU32)>,
    ipv6: Option<(Ipv6Addr, NonZeroU32)>,
}

#[derive(Clone)]
pub struct Dialer {
    ip_version: crate::config::IpVersion,
    initialization: Arc<SocketInitialization>,
    protector: Option<Arc<dyn SocketProtector>>,
    source_binding: Option<SourceBinding>,
    #[cfg(all(windows, feature = "windows-uwp"))]
    interface_binding: Option<InterfaceBinding>,
    ipv6: bool,
    connect_timeout: Duration,
}

impl std::fmt::Debug for Dialer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("Dialer");
        debug
            .field("has_protector", &self.protector.is_some())
            .field("source_binding", &self.source_binding);
        #[cfg(all(windows, feature = "windows-uwp"))]
        debug.field("interface_binding", &self.interface_binding);
        debug
            .field("ipv6", &self.ipv6)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl Default for Dialer {
    fn default() -> Self {
        Self {
            ip_version: crate::config::IpVersion::Dual,
            initialization: Arc::new(SocketInitialization::default()),
            protector: None,
            source_binding: None,
            #[cfg(all(windows, feature = "windows-uwp"))]
            interface_binding: None,
            ipv6: true,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl Dialer {
    pub(crate) fn with_ip_version(mut self, version: crate::config::IpVersion) -> Self {
        self.ip_version = version;
        self
    }
    pub(crate) fn ip_version(&self) -> crate::config::IpVersion {
        self.ip_version
    }
    pub(crate) fn ordered_addresses(&self, addresses: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut addresses = addresses
            .iter()
            .copied()
            .filter(|address| self.ipv6 || address.is_ipv4())
            .collect();
        self.ip_version.order(&mut addresses);
        addresses
    }

    /// Start a new owner for a Running Session or private measurement. Policy
    /// is retained, but stopping one graph must not close another session.
    pub(crate) fn with_fresh_initialization(mut self) -> Self {
        self.initialization = Arc::new(SocketInitialization::default());
        self
    }

    pub(crate) fn begin_shutdown(&self) {
        self.initialization.begin_shutdown();
    }

    pub(crate) async fn shutdown(&self) {
        self.initialization.shutdown().await;
    }

    #[must_use]
    pub(crate) const fn with_ipv6(mut self, ipv6: bool) -> Self {
        self.ipv6 = ipv6;
        self
    }

    #[must_use]
    pub fn with_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.protector = Some(protector);
        self
    }

    #[must_use]
    pub const fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_binding = Some(match source_ip {
            IpAddr::V4(ipv4) => SourceBinding {
                ipv4: Some(ipv4),
                ipv6: None,
            },
            IpAddr::V6(ipv6) => SourceBinding {
                ipv4: None,
                ipv6: Some(ipv6),
            },
        });
        #[cfg(all(windows, feature = "windows-uwp"))]
        {
            self.interface_binding = None;
        }
        self
    }

    #[cfg(all(windows, feature = "windows-uwp"))]
    #[must_use]
    pub(crate) const fn with_windows_interface(
        mut self,
        ipv4: Option<(Ipv4Addr, NonZeroU32)>,
        ipv6: Option<(Ipv6Addr, NonZeroU32)>,
    ) -> Self {
        self.source_binding = None;
        self.interface_binding = Some(InterfaceBinding { ipv4, ipv6 });
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub async fn connect(&self, endpoint: &ResolvedEndpoint) -> io::Result<PhysicalStream> {
        let mut last_error = None;
        for address in self.ordered_addresses(&endpoint.addresses) {
            match self.connect_one(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            if endpoint.addresses.is_empty() {
                io::Error::new(io::ErrorKind::NotFound, "endpoint has no addresses")
            } else {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "endpoint has no permitted addresses",
                )
            }
        }))
    }

    /// Connects a direct TCP socket while applying the same platform protect
    /// hook and timeout used for the proxy-server dial path.
    pub async fn connect_address(&self, address: SocketAddr) -> io::Result<PhysicalStream> {
        self.connect_one(address).await
    }

    /// Creates a direct UDP socket for one destination and applies the
    /// platform protect or binding policy before exposing it to the caller.
    pub async fn bind_udp_for(&self, destination: SocketAddr) -> io::Result<PhysicalDatagram> {
        self.require_permitted(destination)?;
        let ipv6 = destination.is_ipv6();
        let bind_address = self
            .source_address_for(destination)?
            .unwrap_or_else(|| wildcard_address(ipv6));
        let dialer = self.clone();
        let (socket, guard) = self
            .initialization
            .run(move |check| {
                let socket = Socket::new(
                    if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
                    Type::DGRAM,
                    Some(Protocol::UDP),
                )?;
                let guard = track(ResourceKind::Socket);
                check()?;
                #[cfg(all(windows, feature = "windows-uwp"))]
                dialer.apply_interface_binding(socket.as_raw_socket(), destination)?;
                socket.bind(&bind_address.into())?;
                socket.set_nonblocking(true)?;
                check()?;
                dialer.protect_socket(&socket)?;
                check()?;
                Ok((std::net::UdpSocket::from(socket), guard))
            })
            .await?;
        Ok(ObservedIo::with_guard(UdpSocket::from_std(socket)?, guard))
    }

    fn source_address_for(&self, destination: SocketAddr) -> io::Result<Option<SocketAddr>> {
        #[cfg(all(windows, feature = "windows-uwp"))]
        if self.interface_binding.is_some() && destination.ip().is_loopback() {
            return Ok(Some(loopback_address(destination.is_ipv6())));
        }
        self.source_address(destination.is_ipv6())
    }

    fn source_address(&self, ipv6: bool) -> io::Result<Option<SocketAddr>> {
        #[cfg(all(windows, feature = "windows-uwp"))]
        if let Some(binding) = self.interface_binding {
            let source_ip = if ipv6 {
                binding.ipv6.map(|(ip, _)| IpAddr::V6(ip))
            } else {
                binding.ipv4.map(|(ip, _)| IpAddr::V4(ip))
            };
            return source_ip.map(|ip| SocketAddr::new(ip, 0)).map_or_else(
                || {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "no physical interface is bound for the destination address family",
                    ))
                },
                |address| Ok(Some(address)),
            );
        }
        let Some(binding) = self.source_binding else {
            return Ok(None);
        };
        let source_ip = if ipv6 {
            binding.ipv6.map(IpAddr::V6)
        } else {
            binding.ipv4.map(IpAddr::V4)
        };
        source_ip.map(|ip| SocketAddr::new(ip, 0)).map_or_else(
            || {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no source IP is bound for the destination address family",
                ))
            },
            |address| Ok(Some(address)),
        )
    }

    #[cfg(all(windows, feature = "windows-uwp"))]
    fn apply_interface_binding(
        &self,
        socket: RawSocket,
        destination: SocketAddr,
    ) -> io::Result<()> {
        let Some(binding) = self.interface_binding else {
            return Ok(());
        };
        if destination.ip().is_loopback() {
            return Ok(());
        }
        let ipv6 = destination.is_ipv6();
        let index = if ipv6 {
            binding.ipv6.map(|(_, index)| index)
        } else {
            binding.ipv4.map(|(_, index)| index)
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no interface index is bound for the destination address family",
            )
        })?;
        let value = interface_option_value(index, ipv6);
        let (level, option) = if ipv6 {
            (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP.0, IP_UNICAST_IF)
        };
        let socket = usize::try_from(socket)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Windows socket"))?;
        // SAFETY: `socket` is live for the call and `value` is the required DWORD.
        if unsafe { setsockopt(SOCKET(socket), level, option, Some(&value)) } == SOCKET_ERROR {
            // SAFETY: this immediately reads the calling thread's WinSock error.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
        }
        Ok(())
    }

    async fn connect_one(&self, address: SocketAddr) -> io::Result<PhysicalStream> {
        self.require_permitted(address)?;
        let ipv6 = address.is_ipv6();
        let source_address = self.source_address_for(address)?;
        let dialer = self.clone();
        let (socket, guard) = self
            .initialization
            .run(move |check| {
                let socket = if ipv6 {
                    TcpSocket::new_v6()?
                } else {
                    TcpSocket::new_v4()?
                };
                let guard = track(ResourceKind::Socket);
                check()?;
                dialer.protect_socket(&socket)?;
                check()?;
                #[cfg(all(windows, feature = "windows-uwp"))]
                dialer.apply_interface_binding(socket.as_raw_socket(), address)?;
                if let Some(source_address) = source_address {
                    socket.bind(source_address)?;
                }
                check()?;
                Ok((socket, guard))
            })
            .await?;
        let stream = timeout(self.connect_timeout, socket.connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        stream.set_nodelay(true)?;
        Ok(ObservedIo::with_guard(stream, guard))
    }

    #[cfg(unix)]
    fn protect_socket(&self, socket: &impl AsRawFd) -> io::Result<()> {
        self.protector
            .as_ref()
            .map_or(Ok(()), |protector| protector.protect(socket.as_raw_fd()))
    }

    #[cfg(not(unix))]
    fn protect_socket<T>(&self, _socket: &T) -> io::Result<()> {
        if self.protector.is_some() {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "socket protection is only supported on Unix platforms",
            ))
        } else {
            Ok(())
        }
    }

    fn require_permitted(&self, address: SocketAddr) -> io::Result<()> {
        if (!self.ipv6 && address.is_ipv6()) || !self.ip_version.permits(address.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "address family is disabled",
            ));
        }
        Ok(())
    }
}

fn wildcard_address(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::from(([0_u16; 8], 0))
    } else {
        SocketAddr::from(([0_u8; 4], 0))
    }
}

#[cfg(all(windows, feature = "windows-uwp"))]
fn loopback_address(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
    } else {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }
}

#[cfg(all(windows, feature = "windows-uwp"))]
fn interface_option_value(index: NonZeroU32, ipv6: bool) -> [u8; 4] {
    if ipv6 {
        index.get().to_ne_bytes()
    } else {
        index.get().to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::atomic::AtomicUsize;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::atomic::Ordering,
    };

    use tokio::net::TcpListener;

    use super::*;

    #[cfg(unix)]
    struct CountingProtector(AtomicUsize);

    #[cfg(unix)]
    impl SocketProtector for CountingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[cfg(unix)]
    struct RejectingProtector;

    #[cfg(unix)]
    impl SocketProtector for RejectingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "protect rejected",
            ))
        }
    }

    #[tokio::test]
    async fn source_ip_is_selected_and_binds_tcp_and_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let dialer = Dialer::default().with_source_ip(source);
        assert_eq!(
            dialer
                .source_address_for(listener.local_addr().unwrap())
                .unwrap(),
            Some(SocketAddr::new(source, 0))
        );

        let stream = dialer
            .connect_address(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), source);
        assert_eq!(peer.ip(), source);

        let udp = dialer
            .bind_udp_for(SocketAddr::from(([127, 0, 0, 1], 9)))
            .await
            .unwrap();
        assert_eq!(udp.local_addr().unwrap().ip(), source);
    }

    #[tokio::test]
    async fn source_ip_rejects_another_address_family() {
        let dialer = Dialer::default().with_source_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let error = dialer
            .connect_address(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            dialer
                .bind_udp_for("[2001:db8::1]:9".parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn disabled_ipv6_rejects_all_physical_socket_paths() {
        let dialer = Dialer::default().with_ipv6(false);
        let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);
        let endpoint = ResolvedEndpoint {
            logical_host: "localhost".to_owned(),
            port: address.port(),
            addresses: vec![address],
        };

        assert_eq!(
            dialer.connect(&endpoint).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            dialer.connect_address(address).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            dialer.bind_udp_for(address).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(all(windows, feature = "windows-uwp"))]
    #[tokio::test]
    async fn interface_binding_rejects_missing_non_loopback_address_family() {
        let ipv4_only = Dialer::default().with_windows_interface(
            Some((Ipv4Addr::new(192, 0, 2, 10), NonZeroU32::new(10).unwrap())),
            None,
        );
        assert_eq!(
            ipv4_only
                .bind_udp_for("[2001:db8::1]:9".parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(all(windows, feature = "windows-uwp"))]
    #[tokio::test]
    async fn windows_physical_binding_exempts_explicit_loopback_tcp_and_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dialer = Dialer::default().with_windows_interface(
            Some((Ipv4Addr::new(192, 0, 2, 10), NonZeroU32::new(10).unwrap())),
            None,
        );

        let stream = dialer
            .connect_address(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert!(stream.local_addr().unwrap().ip().is_loopback());
        assert!(peer.ip().is_loopback());

        let udp = dialer
            .bind_udp_for(SocketAddr::from(([127, 0, 0, 1], 9)))
            .await
            .unwrap();
        assert_eq!(
            udp.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[cfg(all(windows, feature = "windows-uwp"))]
    #[test]
    fn windows_interface_index_uses_win_sock_byte_order() {
        let index = NonZeroU32::new(0x0102_0304).unwrap();
        assert_eq!(interface_option_value(index, false), [1, 2, 3, 4]);
        assert_eq!(
            interface_option_value(index, true),
            0x0102_0304_u32.to_ne_bytes()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn protector_runs_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let protector = Arc::new(CountingProtector(AtomicUsize::new(0)));
        let dialer = Dialer::default().with_protector(protector.clone());
        let endpoint = ResolvedEndpoint {
            logical_host: "localhost".to_owned(),
            port: address.port(),
            addresses: vec![address],
        };

        let _stream = dialer.connect(&endpoint).await.unwrap();
        assert_eq!(protector.0.load(Ordering::Relaxed), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn protect_failure_prevents_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dialer = Dialer::default().with_protector(Arc::new(RejectingProtector));
        let endpoint = ResolvedEndpoint {
            logical_host: "localhost".to_owned(),
            port: address.port(),
            addresses: vec![address],
        };

        let error = dialer.connect(&endpoint).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn literal_loopback_addresses_do_not_require_dns() {
        for host in ["127.0.0.1", "127.0.0.2", "::1"] {
            let endpoint = SystemResolver.resolve(host, 443).await.unwrap();
            assert_eq!(endpoint.logical_host, host);
            assert_eq!(endpoint.addresses.len(), 1);
            assert!(endpoint.addresses[0].ip().is_loopback());
        }
    }

    #[tokio::test]
    async fn hostnames_resolving_to_loopback_fail_closed() {
        for _ in 0..2 {
            let error = SystemResolver.resolve("localhost", 443).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
        assert!(std::ptr::eq(dns_worker_pool(), dns_worker_pool()));
    }

    #[tokio::test]
    async fn worker_pool_resolves_localhost_concurrently() {
        let pool = Arc::new(DnsWorkerPool::default());
        let barrier = Arc::new(tokio::sync::Barrier::new(MAX_DNS_WORKERS));
        let mut tasks = Vec::new();

        for _ in 0..MAX_DNS_WORKERS {
            let pool = pool.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                pool.resolve("localhost", 443).await
            }));
        }

        for task in tasks {
            let addresses = task.await.unwrap().unwrap();
            assert!(!addresses.is_empty());
            assert!(addresses.len() <= MAX_RESOLVED_ADDRESSES);
            assert!(addresses.iter().all(|address| address.port() == 443));
        }
        assert!((1..=MAX_DNS_WORKERS).contains(&pool.worker_count()));
    }

    #[tokio::test]
    async fn sequential_lookups_lazily_reuse_the_first_worker() {
        let pool = DnsWorkerPool::default();
        assert_eq!(pool.worker_count(), 0);

        for _ in 0..3 {
            let addresses = pool.resolve("localhost", 443).await.unwrap();
            assert!(!addresses.is_empty());
        }

        assert_eq!(pool.worker_count(), 1);
    }

    #[tokio::test]
    async fn worker_pool_waits_instead_of_rejecting_after_four_claimed_slots() {
        let pool = Arc::new(DnsWorkerPool::default());
        let mut leases = Vec::new();
        for _ in 0..MAX_DNS_WORKERS {
            leases.push(pool.claim_worker().await.unwrap());
        }
        assert_eq!(pool.worker_count(), MAX_DNS_WORKERS);

        let waiting_pool = Arc::clone(&pool);
        let mut waiting = tokio::spawn(async move { waiting_pool.claim_worker().await });
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err(),
            "worker request unexpectedly bypassed occupied slots"
        );

        let released = leases.pop().unwrap();
        released.busy.store(false, Ordering::Release);
        pool.available.notify_one();
        let acquired = timeout(Duration::from_secs(1), waiting)
            .await
            .expect("waiting worker was not notified")
            .unwrap()
            .unwrap();
        acquired.busy.store(false, Ordering::Release);

        for lease in leases {
            lease.busy.store(false, Ordering::Release);
        }
    }

    #[test]
    fn resolved_address_collection_enforces_the_limit() {
        let addresses = (1..=MAX_RESOLVED_ADDRESSES + 3)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port as u16)));
        let addresses = take_resolved_addresses(addresses);

        assert_eq!(addresses.len(), MAX_RESOLVED_ADDRESSES);
        assert_eq!(
            addresses.last().unwrap().port(),
            MAX_RESOLVED_ADDRESSES as u16
        );
    }

    #[cfg(all(unix, feature = "ffi"))]
    #[test]
    fn socket_initialization_churn_reclaims_completed_work() {
        use crate::resources::observation::ResourceProbe;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let probe = ResourceProbe::default();
        runtime.block_on(probe.scope(async {
            let protector = Arc::new(CountingProtector(AtomicUsize::new(0)));
            let dialer = Dialer::default().with_protector(protector.clone());
            let destination = SocketAddr::from(([192, 0, 2, 1], 443));
            // Client-only socket setup: no listener, send, or network peer.
            for _ in 0..32 {
                let mut attempts = tokio::task::JoinSet::new();
                for _ in 0..256 {
                    let dialer = dialer.clone();
                    let probe = probe.clone();
                    attempts.spawn(async move {
                        probe
                            .scope(async move {
                                drop(dialer.bind_udp_for(destination).await.unwrap());
                            })
                            .await;
                    });
                }
                while let Some(result) = attempts.join_next().await {
                    result.unwrap();
                }
            }
            dialer.shutdown().await;
            assert_eq!(protector.0.load(Ordering::Relaxed), 8192);
            assert!(probe.snapshot().peak(ResourceKind::Task) <= 64);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            println!("socket initialization churn: {:?}", probe.snapshot());
        }));
    }

    #[cfg(all(unix, feature = "ffi"))]
    #[test]
    fn socket_initialization_cancellation_joins_started_and_queued_work() {
        use crate::resources::observation::ResourceProbe;
        use std::sync::Condvar;

        #[derive(Default)]
        struct GatedProtector {
            released: Mutex<bool>,
            wake: Condvar,
            entered: AtomicUsize,
        }
        impl GatedProtector {
            fn release(&self) {
                *self.released.lock().unwrap() = true;
                self.wake.notify_all();
            }
        }
        impl SocketProtector for GatedProtector {
            fn protect(&self, _socket: i32) -> io::Result<()> {
                self.entered.fetch_add(1, Ordering::Release);
                let released = self.released.lock().unwrap();
                // A timeout keeps even a failing regression from trapping the
                // runtime's synchronous destructor indefinitely.
                let (_released, _) = self
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                    .unwrap();
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test protector rejected before network connect",
                ))
            }
        }
        struct ReleaseOnDrop(Arc<GatedProtector>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.release();
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let probe = ResourceProbe::default();
        runtime.block_on(probe.scope(async {
            let protector = Arc::new(GatedProtector::default());
            let _release = ReleaseOnDrop(protector.clone());
            let dialer = Dialer::default().with_protector(protector.clone());
            let destination = SocketAddr::from(([192, 0, 2, 1], 443));
            let callers_started = Arc::new(AtomicUsize::new(0));
            let mut attempts = tokio::task::JoinSet::new();
            for index in 0..4096 {
                let dialer = dialer.clone();
                let probe = probe.clone();
                let callers_started = callers_started.clone();
                attempts.spawn(async move {
                    probe
                        .scope(async move {
                            callers_started.fetch_add(1, Ordering::Release);
                            if index % 2 == 0 {
                                dialer.connect_address(destination).await.map(drop)
                            } else {
                                dialer.bind_udp_for(destination).await.map(drop)
                            }
                        })
                        .await
                });
            }
            timeout(Duration::from_secs(3), async {
                while callers_started.load(Ordering::Acquire) != 4096
                    || probe.snapshot().current(ResourceKind::Task) < 64
                    || protector.entered.load(Ordering::Acquire) < 4
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(probe.snapshot().current(ResourceKind::Task) <= 64);
            assert!(probe.snapshot().peak(ResourceKind::Task) <= 64);
            println!("socket initialization backlog: {:?}", probe.snapshot());

            attempts.abort_all();
            while let Some(result) = attempts.join_next().await {
                assert!(result.unwrap_err().is_cancelled());
            }
            println!(
                "socket initialization backlog after caller cancellation: {:?}",
                probe.snapshot()
            );
            let mut stopped = Box::pin(dialer.shutdown());
            assert!(
                timeout(Duration::from_millis(20), &mut stopped)
                    .await
                    .is_err(),
                "Stop must not detach a started protect callback"
            );
            let release_started = std::time::Instant::now();
            protector.release();
            timeout(Duration::from_secs(3), &mut stopped).await.unwrap();
            println!(
                "socket initialization release-to-join: {:?}",
                release_started.elapsed()
            );
            drop(stopped);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            assert_eq!(protector.entered.load(Ordering::Acquire), 4);
            assert_eq!(
                dialer.bind_udp_for(destination).await.unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );

            let fresh = dialer
                .with_fresh_initialization()
                .with_protector(Arc::new(CountingProtector(AtomicUsize::new(0))));
            drop(fresh.bind_udp_for(destination).await.unwrap());
            fresh.shutdown().await;
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            println!("socket initialization reclaimed: {:?}", probe.snapshot());
        }));
    }

    #[cfg(all(unix, feature = "ffi"))]
    #[test]
    fn socket_initialization_shared_pool_contention_reclaims_cancelled_work() {
        use crate::resources::observation::ResourceProbe;
        use std::sync::Condvar;

        #[derive(Default)]
        struct BlockingGate {
            released: Mutex<bool>,
            wake: Condvar,
            entered: AtomicUsize,
        }
        impl BlockingGate {
            fn wait(&self) -> bool {
                self.entered.fetch_add(1, Ordering::Release);
                let released = self.released.lock().unwrap();
                // Test-only unrelated work, not a slow protect callback. The
                // timeout and RAII release also cover assertion failures.
                let (released, _) = self
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(10), |released| !*released)
                    .unwrap();
                *released
            }

            fn release(&self) {
                *self.released.lock().unwrap() = true;
                self.wake.notify_all();
            }
        }
        struct ReleaseOnDrop(Arc<BlockingGate>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        struct FastRejectingProtector(AtomicUsize);
        impl SocketProtector for FastRejectingProtector {
            fn protect(&self, _socket: i32) -> io::Result<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test protector rejected before network connect",
                ))
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for submitted in [512, 4096] {
                let probe = ResourceProbe::default();
                let gate = Arc::new(BlockingGate::default());
                let _release = ReleaseOnDrop(gate.clone());
                let mut blockers = Vec::new();
                for _ in 0..4 {
                    let gate = gate.clone();
                    // Deliberately do not inherit the initialization probe:
                    // these jobs belong to the test, not to this Dialer.
                    blockers.push(tokio::task::spawn_blocking(move || gate.wait()));
                }
                timeout(Duration::from_secs(3), async {
                    while gate.entered.load(Ordering::Acquire) != 4 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();

                let protector = Arc::new(FastRejectingProtector(AtomicUsize::new(0)));
                let protector_lease = Arc::downgrade(&protector);
                let dialer = Dialer::default().with_protector(protector.clone());
                let destination = SocketAddr::from(([192, 0, 2, 1], 443));
                let callers_started = Arc::new(AtomicUsize::new(0));
                let mut attempts = tokio::task::JoinSet::new();
                for index in 0..submitted {
                    let dialer = dialer.clone();
                    let probe = probe.clone();
                    let callers_started = callers_started.clone();
                    attempts.spawn(async move {
                        probe
                            .scope(async move {
                                callers_started.fetch_add(1, Ordering::Release);
                                if index % 2 == 0 {
                                    dialer.connect_address(destination).await.map(drop)
                                } else {
                                    dialer.bind_udp_for(destination).await.map(drop)
                                }
                            })
                            .await
                    });
                }
                timeout(Duration::from_secs(3), async {
                    while callers_started.load(Ordering::Acquire) != submitted
                        || probe.snapshot().current(ResourceKind::Task) < 64
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let before_cancel = probe.snapshot();
                assert!(before_cancel.current(ResourceKind::Task) <= 64);
                assert!(before_cancel.peak(ResourceKind::Task) <= 64);
                assert_eq!(before_cancel.current(ResourceKind::Socket), 0);
                assert_eq!(protector.0.load(Ordering::Relaxed), 0);
                println!(
                    "socket initialization shared-pool submitted={submitted} before cancel: {before_cancel:?}"
                );

                // Scope Stop must wake permit waiters without waiting for
                // unrelated blocking jobs or requiring caller aborts.
                dialer.begin_shutdown();
                timeout(Duration::from_secs(3), async {
                    while let Some(result) = attempts.join_next().await {
                        assert_eq!(result.unwrap().unwrap_err().kind(), io::ErrorKind::Interrupted);
                    }
                })
                .await
                .unwrap();
                let after_cancel = probe.snapshot();
                assert!(after_cancel.current(ResourceKind::Task) <= 64);
                assert!(after_cancel.peak(ResourceKind::Task) <= 64);
                assert_eq!(after_cancel.current(ResourceKind::Socket), 0);
                assert_eq!(protector.0.load(Ordering::Relaxed), 0);
                println!(
                    "socket initialization shared-pool submitted={submitted} after Stop cancellation: {after_cancel:?}"
                );

                let release_started = std::time::Instant::now();
                gate.release();
                timeout(Duration::from_secs(3), dialer.shutdown())
                    .await
                    .unwrap();
                let release_to_join = release_started.elapsed();
                for blocker in blockers {
                    assert!(timeout(Duration::from_secs(3), blocker).await.unwrap().unwrap());
                }
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
                assert_eq!(protector.0.load(Ordering::Relaxed), 0);
                assert_eq!(
                    dialer.bind_udp_for(destination).await.unwrap_err().kind(),
                    io::ErrorKind::Interrupted
                );

                // A new lifecycle owner works after the shared pool recovers;
                // the rejecting protector still prevents any TCP connect.
                let fresh = dialer.clone().with_fresh_initialization();
                assert_eq!(
                    probe
                        .scope(fresh.bind_udp_for(destination))
                        .await
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
                fresh.shutdown().await;
                assert_eq!(protector.0.load(Ordering::Relaxed), 1);
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
                drop(fresh);
                drop(dialer);
                drop(protector);
                assert!(protector_lease.upgrade().is_none());
                println!(
                    "socket initialization shared-pool submitted={submitted} release-to-join={release_to_join:?} reclaimed: {:?}",
                    probe.snapshot()
                );
            }
        });
    }
}
