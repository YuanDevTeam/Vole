use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Uri};
use http_io::{
    Download as RecvStream, ResponseFuture, Sender as SendRequest, Upload as SendStream,
};
#[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
use std::sync::{Mutex, Weak};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
    time::Sleep,
};

use crate::dispatch::BoxStream;
mod h2_driver;
mod h3_driver;
pub(crate) use h3_driver::QuicTransport;
mod http_io;
mod packet_up;
mod pool;
mod request;

pub(crate) enum TransportIo {
    Stream(BoxStream),
    Quic(Box<QuicTransport>),
}

const DEFAULT_UPLOAD_CHUNK_SIZE: usize = 64 * 1024;
const MAX_H2_HEADER_LIST_SIZE: u32 = 16 * 1024;
const DEFAULT_H2_SEND_BUFFER_SIZE: usize = 64 * 1024;
const MAX_UPLOAD_RESPONSE_FRAMES_PER_POLL: usize = 16;
const MAX_UPLOAD_RESPONSE_BYTES_PER_POLL: usize = 32 * 1024;
const CLOSE_UPLOAD_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpConfig {
    pub host: String,
    pub path: String,
    pub mode: XHttpMode,
    pub headers: crate::config::XHttpHeaders,
    pub request: Arc<crate::config::XHttpRequestOptions>,
    pub http_version: crate::config::XHttpVersion,
    pub reuse: Option<Arc<crate::config::XHttpReuseConfig>>,
}

impl XHttpConfig {
    pub fn new(
        host: impl Into<String>,
        path: impl Into<String>,
        mode: XHttpMode,
    ) -> io::Result<Self> {
        let host = host.into();
        let path = path.into();
        if host.is_empty()
            || host.len() > 253
            || host.contains('@')
            || host.parse::<http::uri::Authority>().is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XHTTP host",
            ));
        }
        if path.is_empty() || path.len() > 2_048 || !path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XHTTP path",
            ));
        }
        Ok(Self {
            host,
            path,
            mode,
            headers: Default::default(),
            request: Default::default(),
            http_version: Default::default(),
            reuse: None,
        })
    }
}

#[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
pub(crate) use h3_driver::UdpAssociationControl;
#[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
#[derive(Clone, Debug, Default)]
pub(crate) struct UdpAssociationCapture {
    slot: Arc<Mutex<Option<Option<Weak<UdpAssociationControl>>>>>,
}
#[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
impl UdpAssociationCapture {
    fn report(&self, control: Option<Weak<UdpAssociationControl>>) {
        let mut slot = self.slot.lock().unwrap();
        let value = if slot.is_none() { control } else { None };
        *slot = Some(value);
    }
    pub(crate) fn take(&self) -> Option<Weak<UdpAssociationControl>> {
        self.slot.lock().unwrap().take().flatten()
    }
}

#[derive(Debug, Clone)]
pub struct XHttpClient {
    mode: XHttpMode,
    request: RequestTemplate,
    send_buffer_size: usize,
    upload_chunk_size: usize,
    shared_packet_up: bool,
    http_version: crate::config::XHttpVersion,
    owner: Arc<DriverOwner>,
    reuse: Option<Arc<crate::config::XHttpReuseConfig>>,
    pool: Arc<pool::Pool>,
}

#[derive(Debug)]
struct ConnectionLease {
    _driver: Arc<ConnectionGuard>,
    _usage: Option<pool::Usage>,
}

impl From<Arc<ConnectionGuard>> for ConnectionLease {
    fn from(driver: Arc<ConnectionGuard>) -> Self {
        Self {
            _driver: driver,
            _usage: None,
        }
    }
}

impl XHttpClient {
    #[must_use]
    pub fn new(config: XHttpConfig) -> Self {
        let XHttpConfig {
            host,
            path,
            mode,
            headers,
            request,
            http_version,
            reuse,
        } = config;
        Self {
            mode,
            request: RequestTemplate {
                host: Arc::from(host),
                path: Arc::from(path),
                headers,
                options: request,
            },
            send_buffer_size: DEFAULT_H2_SEND_BUFFER_SIZE,
            upload_chunk_size: DEFAULT_UPLOAD_CHUNK_SIZE,
            shared_packet_up: false,
            http_version,
            owner: Arc::default(),
            pool: Arc::new(pool::Pool::new(reuse.clone(), http_version)),
            reuse,
        }
    }

    /// Immutable upload purpose, established before the first pool acquisition.
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn set_shared_packet_up_transport(&mut self, shared: bool) {
        #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
        let previous = self.udp_budget_qualified();
        self.shared_packet_up = shared;
        #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
        if previous != self.udp_budget_qualified() {
            // Eligibility isolates pools even while both initial budgets are64.
            self.pool = Arc::new(pool::Pool::new(self.reuse.clone(), self.http_version));
        }
    }
    #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
    fn udp_budget_qualified(&self) -> bool {
        self.shared_packet_up
            && self.http_version == crate::config::XHttpVersion::Http3
            && self.mode == XHttpMode::PacketUp
            && matches!(
                &self.request.options.data,
                crate::config::xhttp::DataPlacement::Body
            )
    }

    /// Opt-in only after the VLESS leg proves immutable physical/security scope.
    #[cfg(feature = "outbound-vless")]
    pub(crate) fn enable_active_h2_reuse(&mut self) {
        if self.http_version == crate::config::XHttpVersion::Http2 && self.reuse.is_none() {
            self.pool = Arc::new(pool::Pool::active_h2());
        }
    }

    #[cfg(feature = "outbound-vless")]
    pub(crate) fn uses_active_h2_reuse(&self) -> bool {
        self.http_version == crate::config::XHttpVersion::Http2
            && self.reuse.is_none()
            && self.pool.shares_active()
    }

    /// A context requesting a fresh physical socket keeps the original owner
    /// and request template, but cannot read or populate the active candidate pool.
    #[cfg(feature = "outbound-vless")]
    pub(crate) fn h2_lease(&self, allow_reuse: bool) -> std::borrow::Cow<'_, Self> {
        if self.uses_active_h2_reuse() && !allow_reuse {
            let mut independent = self.clone();
            independent.pool = Arc::new(pool::Pool::new(None, self.http_version));
            std::borrow::Cow::Owned(independent)
        } else {
            std::borrow::Cow::Borrowed(self)
        }
    }

    pub(crate) fn new_with_limits(
        config: XHttpConfig,
        send_buffer_size: usize,
        upload_chunk_size: usize,
    ) -> io::Result<Self> {
        if send_buffer_size == 0 || send_buffer_size > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP send buffer size must be between 1 and u32::MAX bytes",
            ));
        }
        if upload_chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP upload chunk size must be greater than zero",
            ));
        }
        let mut client = Self::new(config);
        client.send_buffer_size = send_buffer_size;
        client.upload_chunk_size = upload_chunk_size;
        Ok(client)
    }

    /// Returns an XHTTP logical connection. Like Mihomo's XHTTP connection,
    /// `shutdown()` closes both directions; it is not a TCP half-close.
    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        if self.owner.cancellation.is_cancelled() {
            return Err(connection_closed());
        }
        if self.http_version == crate::config::XHttpVersion::Http1
            && self.mode != XHttpMode::StreamOne
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP HTTP/1 split mode requires two supplied connections",
            ));
        }
        let (sender, connection) = self.handshake(stream).await?;
        self.connect_http(sender, connection.into()).await
    }

    async fn connect_http(
        &self,
        sender: SendRequest,
        connection: ConnectionLease,
    ) -> io::Result<BoxStream> {
        match self.mode {
            XHttpMode::StreamOne => self.connect_stream_one(sender, connection).await,
            XHttpMode::StreamUp => {
                let download_sender = sender.clone();
                self.connect_stream_up_with_download(
                    sender,
                    self,
                    download_sender,
                    ConnectionGuards::single(connection),
                )
                .await
            }
            XHttpMode::PacketUp => {
                let download_sender = sender.clone();
                self.connect_packet_up_with_download(
                    sender,
                    self,
                    download_sender,
                    ConnectionGuards::single(connection),
                )
                .await
            }
        }
    }

    /// Opens a logical session, dialing only when no reusable physical transport
    /// is available. The caller's absolute setup deadline is never reset.
    pub async fn open<F, Fut>(
        &self,
        deadline: tokio::time::Instant,
        mut connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<BoxStream>>,
    {
        self.open_transport(deadline, || {
            let next = connect();
            async { next.await.map(TransportIo::Stream) }
        })
        .await
    }

    pub(crate) async fn open_transport<F, Fut>(
        &self,
        deadline: tokio::time::Instant,
        connect: F,
    ) -> io::Result<BoxStream>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<TransportIo>>,
    {
        self.open_transport_inner(
            deadline,
            connect,
            #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
            None,
        )
        .await
    }
    #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
    pub(crate) async fn open_transport_captured<F, Fut>(
        &self,
        deadline: tokio::time::Instant,
        connect: F,
        capture: &UdpAssociationCapture,
    ) -> io::Result<BoxStream>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<TransportIo>>,
    {
        self.open_transport_inner(deadline, connect, Some(capture))
            .await
    }

    async fn open_transport_inner<F, Fut>(
        &self,
        deadline: tokio::time::Instant,
        mut connect: F,
        #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))] capture: Option<
            &UdpAssociationCapture,
        >,
    ) -> io::Result<BoxStream>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<TransportIo>>,
    {
        let operation = async {
            let (sender, driver) = self.acquire(false, &mut connect).await?;
            #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
            let control = match &sender {
                SendRequest::H3(sender) => sender.udp_control.as_ref().map(Arc::downgrade),
                _ => None,
            };
            if self.needs_separate_download() {
                let (download, download_driver) =
                    self.handshake_transport(connect().await?).await?;
                return self
                    .connect_split(
                        sender,
                        self,
                        download,
                        ConnectionGuards::split(driver, download_driver.into()),
                    )
                    .await;
            }
            let connected = self.connect_http(sender, driver).await?;
            #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
            if let Some(capture) = capture {
                capture.report(control);
            }
            Ok(connected)
        };
        tokio::select! {biased;
            () = self.owner.cancellation.cancelled() => Err(connection_closed()),
            result = tokio::time::timeout_at(deadline, operation) => result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }

    pub async fn open_with_download<U, D, UF, DF>(
        &self,
        deadline: tokio::time::Instant,
        download_client: &Self,
        upload: U,
        download: D,
    ) -> io::Result<BoxStream>
    where
        U: FnOnce() -> UF,
        D: FnOnce() -> DF,
        UF: Future<Output = io::Result<BoxStream>>,
        DF: Future<Output = io::Result<BoxStream>>,
    {
        self.open_with_download_transports(
            deadline,
            download_client,
            || async { upload().await.map(TransportIo::Stream) },
            || async { download().await.map(TransportIo::Stream) },
        )
        .await
    }

    pub(crate) async fn open_with_download_transports<U, D, UF, DF>(
        &self,
        deadline: tokio::time::Instant,
        download_client: &Self,
        upload: U,
        download: D,
    ) -> io::Result<BoxStream>
    where
        U: FnOnce() -> UF,
        D: FnOnce() -> DF,
        UF: Future<Output = io::Result<TransportIo>>,
        DF: Future<Output = io::Result<TransportIo>>,
    {
        if self.mode == XHttpMode::StreamOne {
            return Err(request::invalid_request());
        }
        let operation = async {
            let up = self.acquire(false, upload);
            let down = download_client.acquire(true, download);
            let ((upload_sender, upload_connection), (download_sender, download_connection)) =
                tokio::try_join!(up, down)?;
            self.connect_split(
                upload_sender,
                download_client,
                download_sender,
                ConnectionGuards::split(upload_connection, download_connection),
            )
            .await
        };
        tokio::select! {biased;
            () = self.owner.cancellation.cancelled() => Err(connection_closed()),
            () = download_client.owner.cancellation.cancelled() => Err(connection_closed()),
            result = tokio::time::timeout_at(deadline,operation) => result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }

    async fn acquire<F, Fut>(
        &self,
        download: bool,
        connect: F,
    ) -> io::Result<(SendRequest, ConnectionLease)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<TransportIo>>,
    {
        let policy = if self.http_version != crate::config::XHttpVersion::Http1 {
            pool::Policy::Multiplexed
        } else if !download && self.mode == XHttpMode::PacketUp {
            pool::Policy::Recyclable
        } else {
            pool::Policy::Exclusive
        };
        self.pool
            .acquire(policy, || async {
                self.handshake_transport(connect().await?).await
            })
            .await
    }

    /// Connects XHTTP upload and download over independent secured HTTP/2 streams.
    ///
    /// `self` and `upload_stream` always carry upload requests. The download client and
    /// stream are used only for the stream-down GET. Both legs use the same session ID.
    /// Shutting down the returned stream closes both legs.
    pub async fn connect_with_download(
        &self,
        upload_stream: BoxStream,
        download_client: &XHttpClient,
        download_stream: BoxStream,
    ) -> io::Result<BoxStream> {
        if self.owner.cancellation.is_cancelled()
            || download_client.owner.cancellation.is_cancelled()
        {
            return Err(connection_closed());
        }
        if self.mode == XHttpMode::StreamOne {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP stream-one cannot use independent download settings",
            ));
        }

        let (upload_sender, upload_connection) = self.handshake(upload_stream).await?;
        let (download_sender, download_connection) =
            download_client.handshake(download_stream).await?;
        let connections =
            ConnectionGuards::split(upload_connection.into(), download_connection.into());
        self.connect_split(upload_sender, download_client, download_sender, connections)
            .await
    }

    async fn connect_split(
        &self,
        upload_sender: SendRequest,
        download_client: &Self,
        download_sender: SendRequest,
        connections: ConnectionGuards,
    ) -> io::Result<BoxStream> {
        match self.mode {
            XHttpMode::StreamUp => {
                self.connect_stream_up_with_download(
                    upload_sender,
                    download_client,
                    download_sender,
                    connections,
                )
                .await
            }
            XHttpMode::PacketUp => {
                self.connect_packet_up_with_download(
                    upload_sender,
                    download_client,
                    download_sender,
                    connections,
                )
                .await
            }
            XHttpMode::StreamOne => unreachable!("stream-one was rejected before handshaking"),
        }
    }

    async fn handshake(
        &self,
        stream: BoxStream,
    ) -> io::Result<(SendRequest, Arc<ConnectionGuard>)> {
        self.handshake_transport(TransportIo::Stream(stream)).await
    }

    pub(crate) fn http_version(&self) -> crate::config::XHttpVersion {
        self.http_version
    }

    #[cfg(feature = "interop-test")]
    pub(crate) fn quic_pings(&self) -> Vec<u64> {
        self.pool.quic_pings()
    }

    fn handshake_transport(
        &self,
        transport: TransportIo,
    ) -> futures_util::future::BoxFuture<'_, io::Result<(SendRequest, Arc<ConnectionGuard>)>> {
        Box::pin(async move {
            tokio::select! {biased;
                () = self.owner.cancellation.cancelled() => Err(connection_closed()),
                result = async {
                    match transport {
                        TransportIo::Stream(stream) if self.http_version != crate::config::XHttpVersion::Http3 => self.handshake_active(stream).await,
                        TransportIo::Quic(transport) if self.http_version == crate::config::XHttpVersion::Http3 => h3_driver::connect(*transport, self.reuse.as_ref().map_or(0, |r| r.keep_alive_seconds),
                            #[cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
                            self.udp_budget_qualified(),
                            &self.owner).await,
                        _ => Err(request::invalid_request()),
                    }
                } => result,
            }
        })
    }

    async fn handshake_active(
        &self,
        stream: BoxStream,
    ) -> io::Result<(SendRequest, Arc<ConnectionGuard>)> {
        if self.http_version == crate::config::XHttpVersion::Http1 {
            return http_io::http1(stream, &self.owner)
                .await
                .map(|(sender, guard)| (sender, Arc::new(guard)));
        }
        #[cfg(feature = "outbound-vless")]
        let private_active_h2 = self.uses_active_h2_reuse();
        #[cfg(not(feature = "outbound-vless"))]
        let private_active_h2 = false;
        h2_driver::connect(
            stream,
            self.send_buffer_size,
            self.reuse
                .as_ref()
                .map_or(0, |options| options.keep_alive_seconds),
            &self.owner,
            private_active_h2,
        )
        .await
    }

    pub async fn stop(&self) {
        self.begin_stop();
        self.pool.clear();
        self.owner.tasks.close();
        self.owner.tasks.wait().await;
    }

    pub(crate) fn begin_stop(&self) {
        let _admission = self.owner.admission.lock().unwrap();
        self.owner.cancellation.cancel();
        self.owner.tasks.close();
    }

    pub(crate) fn needs_separate_download(&self) -> bool {
        self.http_version == crate::config::XHttpVersion::Http1 && self.mode != XHttpMode::StreamOne
    }

    async fn connect_stream_one(
        &self,
        sender: SendRequest,
        connection: ConnectionLease,
    ) -> io::Result<BoxStream> {
        let mut sender = sender;
        let request = self.stream_request(Method::POST, None, None, true)?;
        let (response, upload) = sender.send_request(request, false).await?;
        Ok(Box::new(XHttpStream::new(StreamOne {
            upload,
            download: Downlink::pending(response, "stream-one", true),
            upload_chunk_size: self.upload_chunk_size,
            send_closed: false,
            _connection: connection,
        })))
    }

    fn packet_up_writer(
        &self,
        sender: SendRequest,
        session: Arc<str>,
    ) -> io::Result<packet_up::Writer> {
        let overlap = self.shared_packet_up
            && self.mode == XHttpMode::PacketUp
            && matches!(&sender, SendRequest::H3(_))
            && matches!(
                &self.request.options.data,
                crate::config::xhttp::DataPlacement::Body
            );
        if overlap {
            packet_up::Writer::new_overlapping(
                sender,
                self.request.clone(),
                session,
                self.upload_chunk_size,
                &self.owner,
            )
        } else {
            packet_up::Writer::new(
                sender,
                self.request.clone(),
                session,
                self.upload_chunk_size,
                &self.owner,
            )
        }
    }

    async fn connect_packet_up_with_download(
        &self,
        upload_sender: SendRequest,
        download_client: &XHttpClient,
        download_sender: SendRequest,
        connections: ConnectionGuards,
    ) -> io::Result<BoxStream> {
        let session_id: Arc<str> = Arc::from(self.request.options.session_id.generate());
        let mut download_sender = download_sender;
        let request =
            download_client.stream_request(Method::GET, Some(session_id.as_ref()), None, false)?;
        let (response, _) = download_sender.send_request(request, true).await?;

        Ok(Box::new(XHttpStream::new(PacketUp {
            upload: self.packet_up_writer(upload_sender, session_id)?,
            download: Downlink::pending(response, "packet-up download", false),
            closed: false,
            _connections: connections,
        })))
    }

    async fn connect_stream_up_with_download(
        &self,
        upload_sender: SendRequest,
        download_client: &XHttpClient,
        download_sender: SendRequest,
        connections: ConnectionGuards,
    ) -> io::Result<BoxStream> {
        let session_id: Arc<str> = Arc::from(self.request.options.session_id.generate());
        let mut download_sender = download_sender;
        let request =
            download_client.stream_request(Method::GET, Some(session_id.as_ref()), None, false)?;
        let (download_response, _) = download_sender.send_request(request, true).await?;

        let mut upload_sender = upload_sender;
        let request = self.stream_request(Method::POST, Some(session_id.as_ref()), None, true)?;
        let (upload_response, upload) = upload_sender.send_request(request, false).await?;

        Ok(Box::new(XHttpStream::new(StreamUp {
            upload,
            upload_response: UploadResponse::pending(upload_response),
            download: Downlink::pending(download_response, "stream-up download", false),
            upload_chunk_size: self.upload_chunk_size,
            send_closed: false,
            _connections: connections,
        })))
    }

    fn stream_request(
        &self,
        method: Method,
        session_id: Option<&str>,
        sequence: Option<u64>,
        grpc_content_type: bool,
    ) -> io::Result<Request<()>> {
        self.request
            .build(method, session_id, sequence, grpc_content_type)
    }
}

// Mihomo's Relay falls back to Conn.Close because XHTTP has no CloseWrite.
// Keep that contract local to XHTTP: callers and other protocols retain their
// normal AsyncWrite shutdown behavior. Dropping the inner connection releases
// both HTTP legs, buffered responses and the owned connection drivers.
struct XHttpStream<T> {
    inner: Option<T>,
    reader_waker: Option<Waker>,
    close_deadline: Option<Pin<Box<Sleep>>>,
}

impl<T> XHttpStream<T> {
    fn new(inner: T) -> Self {
        Self {
            inner: Some(inner),
            reader_waker: None,
            close_deadline: None,
        }
    }

    fn close(&mut self) {
        self.inner = None;
        self.close_deadline = None;
        if let Some(waker) = self.reader_waker.take() {
            waker.wake();
        }
    }
}

fn connection_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP connection is closed")
}

impl<T: AsyncRead + Unpin> AsyncRead for XHttpStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(connection_closed()));
        };
        let result = Pin::new(inner).poll_read(cx, output);
        self.reader_waker = result.is_pending().then(|| cx.waker().clone());
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for XHttpStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.close_deadline.is_some() {
            return Poll::Ready(Err(connection_closed()));
        }
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_write(cx, input),
            None => Poll::Ready(Err(connection_closed())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Err(connection_closed())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if let Poll::Ready(result) = Pin::new(inner).poll_shutdown(cx) {
            // Close the reader even if ending/flushing the upload failed.
            self.close();
            return Poll::Ready(result);
        }
        // Mihomo's packet-up Close waits at most one second for its pending
        // upload flush, then cancels it. A stalled POST must not pin the reader.
        let deadline = self
            .close_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(CLOSE_UPLOAD_TIMEOUT)));
        if deadline.as_mut().poll(cx).is_ready() {
            self.close();
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

#[derive(Debug, Clone)]
struct RequestTemplate {
    host: Arc<str>,
    path: Arc<str>,
    headers: crate::config::XHttpHeaders,
    options: Arc<crate::config::XHttpRequestOptions>,
}

impl RequestTemplate {
    fn build(
        &self,
        method: Method,
        session_id: Option<&str>,
        sequence: Option<u64>,
        grpc_content_type: bool,
    ) -> io::Result<Request<()>> {
        use crate::config::xhttp::MetaPlacement;
        let base = if self.options.session == MetaPlacement::Path
            || self.options.sequence == MetaPlacement::Path
        {
            build_uri(self.host.as_ref(), self.path.as_ref(), None, None)?
        } else {
            Uri::builder()
                .scheme("https")
                .authority(self.host.as_ref())
                .path_and_query(self.path.as_ref())
                .build()
                .map_err(|_| request::invalid_request())?
        };
        let method = if method == Method::GET {
            method
        } else {
            self.options.uplink_method.clone()
        };
        let mut builder = Request::builder().method(method).uri(base.clone());
        *builder.headers_mut().expect("valid request") = self.headers.as_map().clone();
        if grpc_content_type && !self.options.no_grpc_header {
            builder = builder.header("content-type", "application/grpc");
        }
        let mut request = builder.body(()).map_err(io_other)?;
        request::apply_padding(&mut request, &base, &self.options.padding)?;
        if let Some(session_id) = session_id {
            request::apply_metadata(&mut request, &self.options.session, session_id)?;
        }
        if let Some(sequence) = sequence {
            request::apply_metadata(&mut request, &self.options.sequence, &sequence.to_string())?;
        }
        request::check_size(&request)?;
        Ok(request)
    }
}

struct ConnectionGuard {
    task: JoinHandle<()>,
    cancel: Option<tokio_util::sync::CancellationToken>,
}

#[derive(Debug, Default)]
struct DriverOwner {
    admission: std::sync::Mutex<()>,
    cancellation: tokio_util::sync::CancellationToken,
    tasks: tokio_util::task::TaskTracker,
}

impl DriverOwner {
    fn spawn(
        &self,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<ConnectionGuard> {
        let _admission = self.admission.lock().unwrap();
        if self.cancellation.is_cancelled() {
            return Err(connection_closed());
        }
        let token = self.cancellation.clone();
        let observation =
            crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
        let task = self
            .tasks
            .spawn(crate::resources::observation::bind(async move {
                let _observation = observation;
                tokio::select! {biased; ()=token.cancelled()=>{}, ()=future=>{} }
            }));
        Ok(ConnectionGuard { task, cancel: None })
    }

    fn spawn_managed(
        &self,
        future: impl Future<Output = ()> + Send + 'static,
        cancel: tokio_util::sync::CancellationToken,
    ) -> io::Result<ConnectionGuard> {
        let _admission = self.admission.lock().unwrap();
        if self.cancellation.is_cancelled() {
            return Err(connection_closed());
        }
        let observation =
            crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
        let task = self
            .tasks
            .spawn(crate::resources::observation::bind(async move {
                let _observation = observation;
                future.await;
            }));
        Ok(ConnectionGuard {
            task,
            cancel: Some(cancel),
        })
    }
}

impl Drop for DriverOwner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.close();
    }
}

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionGuard")
            .finish_non_exhaustive()
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        } else {
            self.task.abort();
        }
    }
}

#[derive(Debug)]
struct ConnectionGuards {
    _upload: ConnectionLease,
    _download: Option<ConnectionLease>,
}

impl ConnectionGuards {
    fn permit_upload_recycle(&mut self) {
        if let Some(usage) = &mut self._upload._usage {
            usage.permit_recycle();
        }
    }
    fn single(connection: ConnectionLease) -> Self {
        Self {
            _upload: connection,
            _download: None,
        }
    }

    fn split(upload: ConnectionLease, download: ConnectionLease) -> Self {
        Self {
            _upload: upload,
            _download: Some(download),
        }
    }
}

enum DownlinkState {
    Pending {
        response: Pin<Box<ResponseFuture>>,
        operation: &'static str,
        allow_other_success: bool,
    },
    Active(RecvStream),
    Eof,
}

struct Downlink {
    state: DownlinkState,
    current: Bytes,
}

impl Downlink {
    fn pending(
        response: ResponseFuture,
        operation: &'static str,
        allow_other_success: bool,
    ) -> Self {
        Self {
            state: DownlinkState::Pending {
                response: Box::pin(response),
                operation,
                allow_other_success,
            },
            current: Bytes::new(),
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || matches!(self.state, DownlinkState::Eof) {
            return Poll::Ready(Ok(()));
        }

        for _ in 0..MAX_UPLOAD_RESPONSE_FRAMES_PER_POLL {
            if self.current.has_remaining() {
                let count = self.current.remaining().min(output.remaining());
                output.put_slice(&self.current[..count]);
                self.current.advance(count);
                let DownlinkState::Active(stream) = &mut self.state else {
                    unreachable!("buffered data only exists for an active response")
                };
                stream.release_capacity(count)?;
                return Poll::Ready(Ok(()));
            }

            match &mut self.state {
                DownlinkState::Pending {
                    response,
                    operation,
                    allow_other_success,
                } => match response.as_mut().poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        if let Err(error) =
                            ensure_success(response.status(), operation, *allow_other_success)
                        {
                            self.state = DownlinkState::Eof;
                            return Poll::Ready(Err(error));
                        }
                        self.state = DownlinkState::Active(response.into_body());
                    }
                    Poll::Ready(Err(error)) => {
                        self.state = DownlinkState::Eof;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                DownlinkState::Active(stream) => match stream.poll_data(cx) {
                    Poll::Ready(Some(Ok(data))) => self.current = data,
                    Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                    Poll::Ready(None) => {
                        self.state = DownlinkState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                DownlinkState::Eof => return Poll::Ready(Ok(())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

struct StreamOne {
    upload: SendStream,
    download: Downlink,
    upload_chunk_size: usize,
    send_closed: bool,
    _connection: ConnectionLease,
}

impl AsyncRead for StreamOne {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.download.poll_read(cx, output)
    }
}

impl AsyncWrite for StreamOne {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP stream-one upload is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let requested = input.len().min(self.upload_chunk_size);
        std::task::ready!(self.upload.poll_flush(cx))?;
        self.upload.reserve_capacity(requested);
        let capacity = self.upload.capacity();
        let capacity = if capacity == 0 {
            match self.upload.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XHTTP stream-one upload was reset",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        } else {
            capacity
        };
        let count = requested.min(capacity);
        self.upload
            .send_data(Bytes::copy_from_slice(&input[..count]), false)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.upload.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.send_closed {
            self.upload.send_data(Bytes::new(), true)?;
            self.send_closed = true;
        }
        self.upload.poll_finish(cx)
    }
}

enum UploadResponseState {
    Pending(Pin<Box<ResponseFuture>>),
    Draining(RecvStream),
    Done,
}

struct UploadResponse {
    state: UploadResponseState,
}

impl UploadResponse {
    fn pending(response: ResponseFuture) -> Self {
        Self {
            state: UploadResponseState::Pending(Box::pin(response)),
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut drained_frames = 0_usize;
        let mut drained_bytes = 0_usize;
        loop {
            match &mut self.state {
                UploadResponseState::Pending(response) => match response.as_mut().poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        if let Err(error) =
                            ensure_success(response.status(), "stream-up upload", true)
                        {
                            self.state = UploadResponseState::Done;
                            return Poll::Ready(Err(error));
                        }
                        self.state = UploadResponseState::Draining(response.into_body());
                    }
                    Poll::Ready(Err(error)) => {
                        self.state = UploadResponseState::Done;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                UploadResponseState::Draining(stream) => match stream.poll_data(cx) {
                    Poll::Ready(Some(Ok(data))) => {
                        drained_frames = drained_frames.saturating_add(1);
                        drained_bytes = drained_bytes.saturating_add(data.len());
                        stream.release_capacity(data.len())?;
                        if upload_response_drain_budget_exhausted(drained_frames, drained_bytes) {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(Some(Err(error))) => {
                        self.state = UploadResponseState::Done;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(None) => {
                        self.state = UploadResponseState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                UploadResponseState::Done => return Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_error(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.poll_drain(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Ok(()),
        }
    }
}

fn upload_response_drain_budget_exhausted(frames: usize, bytes: usize) -> bool {
    frames >= MAX_UPLOAD_RESPONSE_FRAMES_PER_POLL || bytes >= MAX_UPLOAD_RESPONSE_BYTES_PER_POLL
}

struct StreamUp {
    upload: SendStream,
    upload_response: UploadResponse,
    download: Downlink,
    upload_chunk_size: usize,
    send_closed: bool,
    _connections: ConnectionGuards,
}

impl AsyncRead for StreamUp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.upload_response.poll_error(cx) {
            return Poll::Ready(Err(error));
        }
        self.download.poll_read(cx, output)
    }
}

impl AsyncWrite for StreamUp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.upload_response.poll_error(cx) {
            return Poll::Ready(Err(error));
        }
        if self.send_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP stream-up upload is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let requested = input.len().min(self.upload_chunk_size);
        std::task::ready!(self.upload.poll_flush(cx))?;
        self.upload.reserve_capacity(requested);
        let capacity = self.upload.capacity();
        let capacity = if capacity == 0 {
            match self.upload.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XHTTP stream-up upload was reset",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        } else {
            capacity
        };
        let count = requested.min(capacity);
        self.upload
            .send_data(Bytes::copy_from_slice(&input[..count]), false)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.upload_response.poll_error(cx) {
            return Poll::Ready(Err(error));
        }
        self.upload.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.upload_response.poll_error(cx) {
            return Poll::Ready(Err(error));
        }
        if !self.send_closed {
            self.upload.send_data(Bytes::new(), true)?;
            self.send_closed = true;
        }
        self.upload.poll_finish(cx)
    }
}

struct PacketUp {
    upload: packet_up::Writer,
    download: Downlink,
    closed: bool,
    _connections: ConnectionGuards,
}

impl AsyncRead for PacketUp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.upload.check_read(cx)?;
        self.download.poll_read(cx, output)
    }
}

impl AsyncWrite for PacketUp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP packet-up upload is closed",
            )));
        }
        Pin::new(&mut self.upload).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.upload).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.closed = true;
                self._connections.permit_upload_recycle();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

async fn post_packet(sender: SendRequest, request: Request<()>, data: Bytes) -> io::Result<()> {
    let mut sender = sender;
    let empty = data.is_empty();
    let (response, mut upload) = sender.send_request(request, empty).await?;
    if !empty {
        upload.send_data(data, true)?;
    }
    let response = response.await?;
    ensure_success(response.status(), "packet-up upload", false)?;
    let mut body = response.into_body();
    let mut drained = 0usize;
    while let Some(data) = std::future::poll_fn(|cx| body.poll_data(cx)).await {
        let data = data?;
        drained = drained.saturating_add(data.len());
        if drained > request::MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP upload response exceeds its drain budget",
            ));
        }
        body.release_capacity(data.len())?;
        tokio::task::yield_now().await;
    }
    Ok(())
}

fn build_uri(
    host: &str,
    raw_path: &str,
    session_id: Option<&str>,
    sequence: Option<u64>,
) -> io::Result<Uri> {
    let (path, query) = raw_path
        .split_once('?')
        .map_or((raw_path, None), |(path, query)| (path, Some(query)));
    let mut path = normalized_base_path(path);
    if let Some(session_id) = session_id {
        path.push_str(session_id);
    }
    if let Some(sequence) = sequence {
        path.push('/');
        path.push_str(&sequence.to_string());
    }
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        path.push('?');
        path.push_str(query);
    }
    Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query(path)
        .build()
        .map_err(io_other)
}

fn normalized_base_path(raw_path: &str) -> String {
    let path = raw_path.split_once('?').map_or(raw_path, |(path, _)| path);
    let mut path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn ensure_success(
    status: StatusCode,
    operation: &str,
    allow_other_success: bool,
) -> io::Result<()> {
    if status == StatusCode::OK || (allow_other_success && status.is_success()) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "XHTTP {operation} returned HTTP status {status}"
        )))
    }
}

fn io_other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[derive(Default)]
    struct WakeCounter {
        wakes: AtomicUsize,
    }

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn builds_canonical_default_paths() {
        assert_eq!(
            build_uri("example.com", "/x", None, None).unwrap(),
            "https://example.com/x/"
        );
        assert_eq!(
            build_uri("example.com", "/x?ed=1", Some("abc"), Some(7)).unwrap(),
            "https://example.com/x/abc/7?ed=1"
        );
    }

    #[test]
    fn default_and_bounded_clients_keep_distinct_buffer_limits() {
        let config = XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap();
        let default = XHttpClient::new(config.clone());
        assert_eq!(default.send_buffer_size, 64 * 1024);
        assert_eq!(default.upload_chunk_size, 64 * 1024);

        let limited = XHttpClient::new_with_limits(config.clone(), 16 * 1024, 16 * 1024).unwrap();
        assert_eq!(limited.send_buffer_size, 16 * 1024);
        assert_eq!(limited.upload_chunk_size, 16 * 1024);
        assert!(XHttpClient::new_with_limits(config.clone(), 0, 16 * 1024).is_err());
        assert!(XHttpClient::new_with_limits(config, 16 * 1024, 0).is_err());
    }

    #[test]
    fn request_templates_share_static_host_and_path_storage() {
        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
        let cloned = client.request.clone();

        assert!(Arc::ptr_eq(&client.request.host, &cloned.host));
        assert!(Arc::ptr_eq(&client.request.path, &cloned.path));
    }

    #[test]
    fn upload_response_drain_budget_bounds_frames_and_bytes_independently() {
        assert!(!upload_response_drain_budget_exhausted(
            MAX_UPLOAD_RESPONSE_FRAMES_PER_POLL - 1,
            MAX_UPLOAD_RESPONSE_BYTES_PER_POLL - 1,
        ));
        assert!(upload_response_drain_budget_exhausted(
            MAX_UPLOAD_RESPONSE_FRAMES_PER_POLL,
            0,
        ));
        assert!(upload_response_drain_budget_exhausted(
            0,
            MAX_UPLOAD_RESPONSE_BYTES_PER_POLL,
        ));
    }

    fn open_response_peer(server_io: tokio::io::DuplexStream, mode: XHttpMode) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let mut requests = Vec::new();
            let mut responses = Vec::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                let is_download = request.method() == Method::GET || mode == XHttpMode::StreamOne;
                let mut response = respond
                    .send_response(http::Response::new(()), !is_download)
                    .unwrap();
                if is_download {
                    response
                        .send_data(Bytes::from_static(b"ready"), false)
                        .unwrap();
                }
                requests.push(request);
                responses.push(response);
            }
        })
    }

    async fn assert_full_shutdown(mode: XHttpMode, independent_download: bool) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut servers = vec![open_response_peer(server_io, mode)];
        let client = XHttpClient::new(XHttpConfig::new("example.com", "/x", mode).unwrap());
        let mut stream = if independent_download {
            let (download_io, download_server) = tokio::io::duplex(64 * 1024);
            servers.push(open_response_peer(download_server, mode));
            client
                .connect_with_download(Box::new(client_io), &client, Box::new(download_io))
                .await
                .unwrap()
        } else {
            client.connect(Box::new(client_io)).await.unwrap()
        };
        let mut greeting = [0; 5];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"ready");

        let (mut reader, mut writer) = tokio::io::split(stream);
        let (pending, observed_pending) = tokio::sync::oneshot::channel();
        let read = tokio::spawn(async move {
            let mut pending = Some(pending);
            let mut byte = [0];
            let mut output = ReadBuf::new(&mut byte);
            std::future::poll_fn(|cx| {
                let result = Pin::new(&mut reader).poll_read(cx, &mut output);
                if result.is_pending()
                    && let Some(pending) = pending.take()
                {
                    let _ = pending.send(());
                }
                result
            })
            .await
        });
        observed_pending.await.unwrap();
        writer.shutdown().await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), read)
            .await
            .expect("XHTTP shutdown left a blocked downstream reader")
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            writer.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        writer.shutdown().await.unwrap();
        for server in servers {
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("XHTTP connection survived shutdown")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn stream_one_shutdown_closes_both_directions_without_dropping_the_stream() {
        assert_full_shutdown(XHttpMode::StreamOne, false).await;
    }

    #[tokio::test]
    async fn stream_up_shutdown_closes_both_directions_and_download_connections() {
        assert_full_shutdown(XHttpMode::StreamUp, false).await;
        assert_full_shutdown(XHttpMode::StreamUp, true).await;
    }

    #[tokio::test]
    async fn packet_up_shutdown_closes_both_directions_and_download_connections() {
        assert_full_shutdown(XHttpMode::PacketUp, false).await;
        assert_full_shutdown(XHttpMode::PacketUp, true).await;
    }

    #[tokio::test]
    async fn shutdown_discards_buffered_downlink_bytes() {
        for mode in [
            XHttpMode::StreamOne,
            XHttpMode::StreamUp,
            XHttpMode::PacketUp,
        ] {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = open_response_peer(server_io, mode);
            let client = XHttpClient::new(XHttpConfig::new("example.com", "/x", mode).unwrap());
            let mut stream = client.connect(Box::new(client_io)).await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), b'r');
            stream.shutdown().await.unwrap();
            assert_eq!(
                stream.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn shutdown_before_response_headers_releases_the_connection() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (accepted, request_accepted) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_request, _respond) = connection.accept().await.unwrap().unwrap();
            accepted.send(()).unwrap();
            assert!(!matches!(connection.accept().await, Some(Ok(_))));
        });
        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap());
        let mut stream = client.connect(Box::new(client_io)).await.unwrap();
        request_accepted.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn packet_up_shutdown_bounds_a_pending_post_and_rejects_further_io() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (accepted, post_accepted) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_download, mut respond) = connection.accept().await.unwrap().unwrap();
            let _response = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let (_post, _post_response) = connection.accept().await.unwrap().unwrap();
            accepted.send(()).unwrap();
            // Never acknowledge the POST. This is a real HTTP response wait,
            // not a mock of the internal upload future.
            assert!(!matches!(connection.accept().await, Some(Ok(_))));
        });
        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
        let mut stream = client.connect(Box::new(client_io)).await.unwrap();
        stream.write_all(b"pending").await.unwrap();
        // Buffered write completion is not a POST acknowledgement. The owned
        // timer sends without further caller IO; the peer never acknowledges.
        post_accepted.await.unwrap();
        let started = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(2), stream.shutdown())
            .await
            .expect("pending packet-up POST blocked connection close")
            .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            stream.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stream_one_is_a_single_full_duplex_post() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (close_server, keep_server_alive) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.uri().path(), "/x/");
            assert_eq!(request.headers()["content-type"], "application/grpc");
            assert!(
                request.headers()["referer"]
                    .to_str()
                    .unwrap()
                    .contains("x_padding=")
            );

            let handler = tokio::spawn(async move {
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut body = request.into_body();
                let mut received = 0;
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    received += data.len();
                    response.send_data(data, false).unwrap();
                    if received == 5 {
                        break;
                    }
                }
                response.send_data(Bytes::new(), true).unwrap();
                // Retain the request body until the client closes; dropping it
                // now would reset a still-open upload before the reply drains.
                body
            });
            let mut keep_server_alive = keep_server_alive;
            tokio::select! {
                _ = &mut keep_server_alive => {}
                incoming = connection.accept() => {
                    assert!(incoming.is_none(), "unexpected second stream-one request");
                }
            }
            let _body = handler.await.unwrap();
        });

        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap());
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.connect(Box::new(client_io)),
        )
        .await
        .expect("stream-one connect timed out")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.write_all(b"hello"),
        )
        .await
        .expect("stream-one write timed out")
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("stream-one read timed out")
        .unwrap();
        assert_eq!(response, b"hello");
        stream.shutdown().await.unwrap();
        let _ = close_server.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn packet_up_uses_a_download_stream_and_sequenced_posts() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (close_server, keep_server_alive) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (download, mut download_respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(download.method(), Method::GET);
            let session_path = download.uri().path().to_owned();
            let download_stream = download_respond
                .send_response(http::Response::new(()), false)
                .unwrap();

            let (upload, mut upload_respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(upload.method(), Method::POST);
            assert_eq!(upload.uri().path(), format!("{session_path}/0"));
            let handler = tokio::spawn(async move {
                let mut payload = Vec::new();
                let mut body = upload.into_body();
                while let Some(data) = body.data().await {
                    payload.extend_from_slice(&data.unwrap());
                }
                upload_respond
                    .send_response(http::Response::new(()), true)
                    .unwrap();
                let mut download_stream = download_stream;
                download_stream
                    .send_data(Bytes::from(payload), true)
                    .unwrap();
            });
            let mut keep_server_alive = keep_server_alive;
            tokio::select! {
                _ = &mut keep_server_alive => {}
                incoming = connection.accept() => {
                    assert!(incoming.is_none(), "unexpected second packet-up POST");
                }
            }
            handler.await.unwrap();
        });

        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.connect(Box::new(client_io)),
        )
        .await
        .expect("packet-up connect timed out")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.write_all(b"packet"),
        )
        .await
        .expect("packet-up write timed out")
        .unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("packet-up read timed out")
        .unwrap();
        assert_eq!(response, b"packet");
        let _ = close_server.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stream_up_uses_get_and_continuous_post_on_one_connection() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (close_server, keep_server_alive) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (download, mut download_respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(download.method(), Method::GET);
            let session_path = download.uri().path().to_owned();
            let mut download_stream = download_respond
                .send_response(http::Response::new(()), false)
                .unwrap();

            let (upload, mut upload_respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(upload.method(), Method::POST);
            assert_eq!(upload.uri().path(), session_path);
            assert_eq!(upload.headers()["content-type"], "application/grpc");
            upload_respond
                .send_response(http::Response::new(()), true)
                .unwrap();

            let handler = async move {
                let mut payload = Vec::new();
                let mut body = upload.into_body();
                while let Some(data) = body.data().await {
                    payload.extend_from_slice(&data.unwrap());
                    if payload.len() == b"continuous".len() {
                        break;
                    }
                }
                download_stream
                    .send_data(Bytes::from(payload), true)
                    .unwrap();
                body
            };
            tokio::pin!(handler);
            let _body = tokio::select! {
                body = &mut handler => body,
                incoming = connection.accept() => {
                    panic!("stream-up connection ended before upload completed: {incoming:?}")
                }
            };
            let mut keep_server_alive = keep_server_alive;
            tokio::select! {
                _ = &mut keep_server_alive => {}
                incoming = connection.accept() => {
                    assert!(incoming.is_none(), "unexpected third stream-up request");
                }
            }
        });

        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::StreamUp).unwrap());
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.connect(Box::new(client_io)),
        )
        .await
        .expect("stream-up connect timed out")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.write_all(b"continuous"),
        )
        .await
        .expect("stream-up write timed out")
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("stream-up read timed out")
        .unwrap();
        assert_eq!(response, b"continuous");
        stream.shutdown().await.unwrap();
        let _ = close_server.send(());
        server.await.unwrap();
    }

    async fn assert_independent_download(mode: XHttpMode) {
        let (upload_client_io, upload_server_io) = tokio::io::duplex(128 * 1024);
        let (download_client_io, download_server_io) = tokio::io::duplex(128 * 1024);
        let (payload_sender, payload_receiver) =
            tokio::sync::oneshot::channel::<(String, Vec<u8>)>();

        let upload_server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(upload_server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.uri().authority().unwrap(), "upload.example");

            let path = request.uri().path();
            let suffix = path.strip_prefix("/upload/").unwrap();
            let session_id = match mode {
                XHttpMode::PacketUp => {
                    let (session_id, sequence) = suffix.rsplit_once('/').unwrap();
                    assert_eq!(sequence, "0");
                    assert!(!request.headers().contains_key("content-type"));
                    session_id.to_owned()
                }
                XHttpMode::StreamUp => {
                    assert!(!suffix.contains('/'));
                    assert_eq!(request.headers()["content-type"], "application/grpc");
                    suffix.to_owned()
                }
                XHttpMode::StreamOne => unreachable!("split stream-one is rejected"),
            };

            respond
                .send_response(http::Response::new(()), true)
                .unwrap();
            let handler = async move {
                let mut payload = Vec::new();
                let mut body = request.into_body();
                while let Some(data) = body.data().await {
                    payload.extend_from_slice(&data.unwrap());
                    if mode == XHttpMode::StreamUp && payload.len() == b"uplink".len() {
                        break;
                    }
                }
                payload_sender.send((session_id, payload)).unwrap();
                body
            };
            tokio::pin!(handler);
            let _body = tokio::select! {
                body = &mut handler => body,
                incoming = connection.accept() => {
                    panic!("upload connection ended before its request body: {incoming:?}")
                }
            };
            match connection.accept().await {
                None | Some(Err(_)) => {}
                Some(Ok(_)) => panic!("unexpected request on upload connection"),
            }
        });

        let download_server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(download_server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.uri().authority().unwrap(), "download.example");
            let session_id = request
                .uri()
                .path()
                .strip_prefix("/download/")
                .unwrap()
                .to_owned();
            assert!(!session_id.contains('/'));

            let handler = async move {
                let (upload_session_id, payload) = payload_receiver.await.unwrap();
                assert_eq!(upload_session_id, session_id);
                assert_eq!(payload, b"uplink");
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                response
                    .send_data(Bytes::from_static(b"downlink"), true)
                    .unwrap();
            };
            tokio::pin!(handler);
            tokio::select! {
                () = &mut handler => {}
                incoming = connection.accept() => {
                    panic!("download connection ended before the response: {incoming:?}")
                }
            }
            match connection.accept().await {
                None | Some(Err(_)) => {}
                Some(Ok(_)) => panic!("unexpected request on download connection"),
            }
        });

        let upload_client =
            XHttpClient::new(XHttpConfig::new("upload.example", "/upload", mode).unwrap());
        let download_client = XHttpClient::new(
            XHttpConfig::new("download.example", "/download", XHttpMode::PacketUp).unwrap(),
        );
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upload_client.connect_with_download(
                Box::new(upload_client_io),
                &download_client,
                Box::new(download_client_io),
            ),
        )
        .await
        .expect("split XHTTP connect timed out")
        .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.write_all(b"uplink"),
        )
        .await
        .expect("split XHTTP write timed out")
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("split XHTTP read timed out")
        .unwrap();
        assert_eq!(response, b"downlink");
        stream.shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), upload_server)
            .await
            .expect("upload connection task survived the returned stream")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), download_server)
            .await
            .expect("download connection task survived the returned stream")
            .unwrap();
    }

    #[tokio::test]
    async fn packet_up_can_split_upload_and_download_connections() {
        assert_independent_download(XHttpMode::PacketUp).await;
    }

    #[tokio::test]
    async fn stream_up_can_split_upload_and_download_connections() {
        assert_independent_download(XHttpMode::StreamUp).await;
    }

    #[tokio::test]
    async fn stream_up_upload_response_flood_yields_to_split_downlink_and_write() {
        const LARGE_FRAME_BYTES: usize = MAX_UPLOAD_RESPONSE_BYTES_PER_POLL / 2;

        let (upload_client_io, upload_server_io) = tokio::io::duplex(256 * 1024);
        let (download_client_io, download_server_io) = tokio::io::duplex(64 * 1024);
        let (upload_flood_sender, upload_flood_receiver) = tokio::sync::oneshot::channel();
        let (upload_body_sender, upload_body_receiver) = tokio::sync::oneshot::channel();
        let (download_sender, download_receiver) = tokio::sync::oneshot::channel();

        let upload_server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(upload_server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::POST);

            let handler = async move {
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                // The first client poll reaches the frame limit on tiny DATA.
                for _ in 0..MAX_UPLOAD_RESPONSE_FRAMES_PER_POLL {
                    response.send_data(Bytes::from_static(b"x"), false).unwrap();
                }
                // The second reaches the independent byte limit on large DATA.
                // All queued bytes remain below the default HTTP/2 receive
                // window, so both budgets can be exercised without a peer
                // scheduling turn between the two manual client polls.
                for _ in 0..3 {
                    response
                        .send_data(Bytes::from(vec![b'x'; LARGE_FRAME_BYTES]), false)
                        .unwrap();
                }
                // Let the concurrently polled connection flush the queued
                // response frames before the client performs one manual poll.
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                upload_flood_sender.send(()).unwrap();

                let mut body = request.into_body();
                let data = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                upload_body_sender.send(data.to_vec()).unwrap();
                response.send_data(Bytes::new(), true).unwrap();
            };
            tokio::pin!(handler);
            tokio::select! {
                () = &mut handler => {}
                incoming = connection.accept() => {
                    panic!("upload connection ended during response flood: {incoming:?}")
                }
            }
            match connection.accept().await {
                None | Some(Err(_)) => {}
                Some(Ok(_)) => panic!("unexpected request on upload connection"),
            }
        });

        let download_server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(download_server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::GET);
            let mut response = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            response
                .send_data(Bytes::from_static(b"downlink"), true)
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            download_sender.send(()).unwrap();
            match connection.accept().await {
                None | Some(Err(_)) => {}
                Some(Ok(_)) => panic!("unexpected request on download connection"),
            }
        });

        let upload_client = XHttpClient::new(
            XHttpConfig::new("upload.example", "/upload", XHttpMode::StreamUp).unwrap(),
        );
        let download_client = XHttpClient::new(
            XHttpConfig::new("download.example", "/download", XHttpMode::PacketUp).unwrap(),
        );
        let mut stream = upload_client
            .connect_with_download(
                Box::new(upload_client_io),
                &download_client,
                Box::new(download_client_io),
            )
            .await
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), upload_flood_receiver)
            .await
            .expect("upload response flood was not flushed")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), download_receiver)
            .await
            .expect("split downlink was not flushed")
            .unwrap();

        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(counter.clone());
        let mut context = Context::from_waker(&waker);
        let mut bytes = [0_u8; 8];
        let mut output = ReadBuf::new(&mut bytes);
        match Pin::new(stream.as_mut()).poll_read(&mut context, &mut output) {
            Poll::Ready(Ok(())) => {}
            result => panic!("split downlink did not progress in the budgeted poll: {result:?}"),
        }
        assert_eq!(output.filled(), b"downlink");
        assert!(
            counter.wakes.swap(0, Ordering::Relaxed) > 0,
            "frame budget did not self-wake after yielding to the downlink"
        );

        match Pin::new(stream.as_mut()).poll_write(&mut context, b"u") {
            Poll::Ready(Ok(1)) => {}
            result => panic!("split upload did not progress in the budgeted poll: {result:?}"),
        }
        assert!(
            counter.wakes.load(Ordering::Relaxed) > 0,
            "byte budget did not self-wake after yielding to the upload"
        );
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), upload_body_receiver)
                .await
                .expect("split upload did not reach the server")
                .unwrap(),
            b"u"
        );

        drop(stream);
        tokio::time::timeout(std::time::Duration::from_secs(2), upload_server)
            .await
            .expect("upload connection task survived the returned stream")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), download_server)
            .await
            .expect("download connection task survived the returned stream")
            .unwrap();
    }

    #[tokio::test]
    async fn stream_one_rejects_independent_download_before_handshake() {
        let (upload_client_io, _upload_server_io) = tokio::io::duplex(1024);
        let (download_client_io, _download_server_io) = tokio::io::duplex(1024);
        let upload_client = XHttpClient::new(
            XHttpConfig::new("upload.example", "/upload", XHttpMode::StreamOne).unwrap(),
        );
        let download_client = XHttpClient::new(
            XHttpConfig::new("download.example", "/download", XHttpMode::PacketUp).unwrap(),
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upload_client.connect_with_download(
                Box::new(upload_client_io),
                &download_client,
                Box::new(download_client_io),
            ),
        )
        .await
        .expect("stream-one validation attempted an HTTP/2 handshake");
        let error = match result {
            Ok(_) => panic!("stream-one unexpectedly accepted download settings"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn failed_download_handshake_releases_the_upload_connection() {
        let (upload_client_io, upload_server_io) = tokio::io::duplex(16 * 1024);
        let (download_client_io, download_server_io) = tokio::io::duplex(1024);
        drop(download_server_io);

        let upload_server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(upload_server_io).await.unwrap();
            match connection.accept().await {
                None | Some(Err(_)) => {}
                Some(Ok(_)) => panic!("request leaked after the download handshake failed"),
            }
        });
        let upload_client = XHttpClient::new(
            XHttpConfig::new("upload.example", "/upload", XHttpMode::PacketUp).unwrap(),
        );
        let download_client = XHttpClient::new(
            XHttpConfig::new("download.example", "/download", XHttpMode::PacketUp).unwrap(),
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upload_client.connect_with_download(
                Box::new(upload_client_io),
                &download_client,
                Box::new(download_client_io),
            ),
        )
        .await
        .expect("failed download handshake timed out");
        assert!(result.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(2), upload_server)
            .await
            .expect("upload connection leaked after download handshake failure")
            .unwrap();
    }
}

#[cfg(all(test, feature = "outbound-vless", feature = "sing-mux"))]
#[path = "xhttp/h3_packet_overlap_memory_tests.rs"]
mod h3_packet_overlap_memory_tests;
