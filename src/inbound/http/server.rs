use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

pub use crate::config::ProxyCredentials as HttpBasicAuth;
use crate::{
    config::ProxyAccess,
    dispatch::{BoxStream, DispatchError, Dispatcher},
    outbound::{
        MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES, OutboundDiagnostic, capture_outbound_diagnostic,
    },
    session::{InboundKind, InboundMetadata, StreamSession},
};

use super::super::{
    DEFAULT_HEADER_LIMIT,
    listen::{bind_proxy_tcp, bind_tcp},
};
use super::{
    framing::{
        self, Body, RequestPlan, ResponseHead, read_head, timeout_io, transfer_body, write_timed,
    },
    parser::{RequestHead, parse_request_head},
};

pub(crate) const MEASURE_DIAGNOSTIC_HEADER: &str = "X-Vole-Measure-Diagnostic";
pub(crate) const MEASURE_DIAGNOSTIC_REQUEST: &str = "v1";
const MAX_MEASURE_DIAGNOSTIC_HEADER_BYTES: usize = 512;
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub listen: SocketAddr,
    pub auth: Option<HttpBasicAuth>,
    pub ipv6: bool,
    pub header_limit: usize,
    pub header_timeout: Duration,
    pub connect_timeout: Duration,
    pub body_idle_timeout: Duration,
}

impl HttpServerConfig {
    pub fn loopback(listen: SocketAddr, auth: HttpBasicAuth) -> io::Result<Self> {
        if !listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP listener must bind loopback",
            ));
        }
        let mut config = Self::proxy(
            listen.port(),
            ProxyAccess {
                bind_address: None,
                allow_lan: false,
                ipv6: false,
            },
            Some(auth),
        )?;
        config.listen = listen;
        Ok(config)
    }

    pub fn proxy(port: u16, access: ProxyAccess, auth: Option<HttpBasicAuth>) -> io::Result<Self> {
        Ok(Self {
            listen: SocketAddr::from((
                if access.allow_lan {
                    Ipv4Addr::UNSPECIFIED
                } else {
                    Ipv4Addr::LOCALHOST
                },
                port,
            )),
            auth,
            ipv6: access.ipv6,
            header_limit: DEFAULT_HEADER_LIMIT,
            header_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(30),
        })
    }
}

pub struct HttpServer {
    listeners: Vec<TcpListener>,
    config: HttpServerConfig,
    dispatcher: Arc<dyn Dispatcher>,
}

impl HttpServer {
    pub async fn bind(
        config: HttpServerConfig,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> io::Result<Self> {
        if (!config.listen.ip().is_loopback() && !config.listen.ip().is_unspecified())
            || !(1024..=DEFAULT_HEADER_LIMIT).contains(&config.header_limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid HTTP listener configuration",
            ));
        }
        let listeners = if config.ipv6 && config.listen.is_ipv4() {
            bind_proxy_tcp(
                config.listen.port(),
                ProxyAccess {
                    bind_address: None,
                    allow_lan: config.listen.ip().is_unspecified(),
                    ipv6: true,
                },
            )?
        } else {
            vec![bind_tcp(config.listen)?]
        };
        Ok(Self {
            listeners,
            config,
            dispatcher,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listeners[0].local_addr()
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.listeners.iter().map(TcpListener::local_addr).collect()
    }

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        match self.listeners.as_slice() {
            [one] => one.accept().await,
            [ipv4, ipv6] => {
                tokio::select! { result = ipv4.accept() => result, result = ipv6.accept() => result }
            }
            _ => unreachable!("client listener policy binds one or two sockets"),
        }
    }

    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break Ok(()),
                joined = tasks.join_next(), if !tasks.is_empty() => { let _ = joined; }
                accepted = self.accept() => {
                    let (stream, peer) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let dispatcher = self.dispatcher.clone();
                    let config = self.config.clone();
                    let child = cancellation.clone();
                    tasks.spawn(crate::resources::observation::task(async move {
                        let _ = handle_connection(stream, peer, dispatcher, config, child).await;
                    }));
                }
            }
        };
        cancellation.cancel();
        while tasks.join_next().await.is_some() {}
        result
    }
}

pub(crate) async fn handle_connection(
    inbound: TcpStream,
    peer: SocketAddr,
    dispatcher: Arc<dyn Dispatcher>,
    config: HttpServerConfig,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let deadline = Instant::now() + config.header_timeout;
    let local_port = inbound.local_addr()?.port();
    handle_connection_with_deadline(
        inbound,
        peer,
        local_port,
        dispatcher,
        config,
        cancellation,
        deadline,
    )
    .await
}

pub(crate) async fn handle_connection_with_deadline<S>(
    inbound: S,
    peer: SocketAddr,
    local_port: u16,
    dispatcher: Arc<dyn Dispatcher>,
    config: HttpServerConfig,
    cancellation: CancellationToken,
    deadline: Instant,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // This cancellation boundary covers every read, write, handshake and tunnel,
    // including error responses to a client that has stopped reading.
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok(()),
        result = async {
            let (read, mut write) = tokio::io::split(inbound);
            let mut reader = BufReader::with_capacity(framing::COPY_BUFFER, read);
            serve_requests(&mut reader, &mut write, peer, local_port, &dispatcher, &config, deadline).await
        } => result,
    }
}

async fn serve_requests<R, W>(
    reader: &mut R,
    writer: &mut W,
    peer: SocketAddr,
    local_port: u16,
    dispatcher: &Arc<dyn Dispatcher>,
    config: &HttpServerConfig,
    first_deadline: Instant,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut deadline = first_deadline;
    loop {
        let request = timeout_at(deadline, async {
            if reader.fill_buf().await?.is_empty() {
                return Ok(None);
            }
            let bytes = read_head(reader, config.header_limit).await?;
            parse_request_head(&bytes, Vec::new()).map(Some)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP operation timed out"))
        .and_then(|request| request);
        let request = match request {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(error) => {
                let status = match error.kind() {
                    io::ErrorKind::TimedOut => 408,
                    io::ErrorKind::FileTooLarge => 431,
                    _ => 400,
                };
                write_error(writer, status).await?;
                return Err(error);
            }
        };
        let user = match &config.auth {
            Some(auth) => match auth.authenticate_headers(&request.headers) {
                Some(user) => Some(user),
                None => {
                    write_auth_required(writer).await?;
                    return Ok(());
                }
            },
            None => None,
        };
        let diagnostic = request.is_connect()
            && config.auth.is_some()
            && config.listen.ip().is_loopback()
            && peer.ip().is_loopback()
            && requests_measure_diagnostic(&request.headers);
        let forward = if request.is_connect() {
            framing::validate_connect(&request)
                .and_then(|()| request.connect_destination().map(|target| (target, None)))
        } else {
            RequestPlan::new(&request).map(|plan| (plan.destination.clone(), Some(plan)))
        };
        let (destination, plan) = match forward {
            Ok(value) => value,
            Err(error) => {
                write_error(writer, 400).await?;
                return Err(error);
            }
        };
        let mut session = StreamSession {
            metadata: InboundMetadata { local_port, user },
            inbound: if request.is_connect() {
                InboundKind::Https
            } else {
                InboundKind::Http
            },
            source: peer,
            destination,
            sniffed_domain: None,
        };
        let sniff = dispatcher
            .sniff_plan(peer, &session.destination)
            .await
            .filter(|plan| plan.tcp_enabled());
        if let (Some(forward), Some(sniff)) = (&plan, &sniff) {
            let _prefix = sniff
                .sniff(&mut forward.head.as_slice(), &mut session)
                .await;
        }
        if plan.is_none()
            && let Some(sniff) = sniff
        {
            write_timed(
                writer,
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                config.header_timeout,
            )
            .await?;
            let prefix = sniff.sniff(reader, &mut session).await;
            let mut outbound = timeout(config.connect_timeout, dispatcher.connect_tcp(session))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HTTP outbound connect timed out")
                })?
                .map_err(dispatch_to_io)?;
            if !prefix.is_empty() {
                write_timed(&mut outbound, &prefix, config.connect_timeout).await?;
            }
            let (mut remote_read, mut remote_write) = tokio::io::split(outbound);
            return relay(reader, writer, &mut remote_read, &mut remote_write).await;
        }
        let outbound = connect(dispatcher, session, config, writer, diagnostic).await?;
        if let Some(plan) = plan {
            if !forward_request(reader, writer, outbound, &request, plan, config).await? {
                return Ok(());
            }
            deadline = Instant::now() + config.header_timeout;
        } else {
            write_timed(
                writer,
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                config.header_timeout,
            )
            .await?;
            let (mut remote_read, mut remote_write) = tokio::io::split(outbound);
            return relay(reader, writer, &mut remote_read, &mut remote_write).await;
        }
    }
}

async fn forward_request<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut outbound: BoxStream,
    request: &RequestHead,
    plan: RequestPlan,
    config: &HttpServerConfig,
) -> io::Result<bool>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_timed(&mut outbound, &plan.head, config.connect_timeout).await?;
    let (remote_read, mut remote_write) = tokio::io::split(outbound);
    let mut remote_read = BufReader::with_capacity(framing::COPY_BUFFER, remote_read);
    let mut uploading = Box::pin(transfer_body(
        reader,
        &mut remote_write,
        plan.body,
        config.body_idle_timeout,
        &plan.trailer_blocklist,
        false,
    ));
    let mut uploaded = false;
    let mut informational = 0;
    let response = loop {
        let mut reading = Box::pin(async {
            // Waiting for the first response byte may overlap a large upload.
            // Once headers begin, their total read deadline is absolute.
            if remote_read.fill_buf().await?.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing HTTP response",
                ));
            }
            let bytes = timeout_io(
                config.header_timeout,
                read_head(&mut remote_read, config.header_limit),
            )
            .await?;
            ResponseHead::parse(&bytes)
        });
        let response = loop {
            if uploaded {
                break timeout_io(config.header_timeout, &mut reading).await;
            }
            tokio::select! {
                biased;
                result = &mut uploading => {
                    if let Err(error) = result {
                        write_error(writer, if error.kind() == io::ErrorKind::TimedOut { 408 } else { 400 }).await?;
                        return Err(error);
                    }
                    uploaded = true;
                }
                response = &mut reading => break response,
            }
        };
        let response = match response {
            Ok(value) => value,
            Err(error) => {
                write_error(
                    writer,
                    if error.kind() == io::ErrorKind::TimedOut {
                        504
                    } else {
                        502
                    },
                )
                .await?;
                return Err(error);
            }
        };
        if response.status < 200 && response.status != 101 {
            informational += 1;
            if informational > MAX_INFORMATIONAL_RESPONSES {
                write_error(writer, 502).await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many informational responses",
                ));
            }
            if request.version == "HTTP/1.1" {
                write_timed(
                    writer,
                    &response.encode(false, false, false),
                    config.header_timeout,
                )
                .await?;
            }
            continue;
        }
        break response;
    };
    // An early final response cancels the upload and closes this client
    // connection. Unread request bytes can never become a second request.
    drop(uploading);
    if response.status == 101 {
        if !uploaded || !response.valid_upgrade(&plan.upgrade).unwrap_or(false) {
            write_error(writer, 502).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP protocol switch",
            ));
        }
        write_timed(
            writer,
            &response.encode(false, true, false),
            config.header_timeout,
        )
        .await?;
        relay(reader, writer, &mut remote_read, &mut remote_write).await?;
        return Ok(false);
    }
    let body = response.body(&request.method);
    let legacy = request.version == "HTTP/1.0";
    let dechunk = legacy && body == Body::Chunked;
    let keep_alive = plan.keep_alive && uploaded && body != Body::UntilEof && !dechunk;
    write_timed(
        writer,
        &response.encode(keep_alive, false, legacy),
        config.header_timeout,
    )
    .await?;
    transfer_body(
        &mut remote_read,
        writer,
        body,
        config.body_idle_timeout,
        response.trailer_blocklist(),
        dechunk,
    )
    .await?;
    Ok(keep_alive)
}

async fn relay<R, W, RR, RW>(
    reader: &mut R,
    writer: &mut W,
    remote_read: &mut RR,
    remote_write: &mut RW,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
{
    let upload = async {
        tokio::io::copy(reader, remote_write).await?;
        remote_write.shutdown().await
    };
    let download = async {
        tokio::io::copy(remote_read, writer).await?;
        writer.shutdown().await
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn connect<W: AsyncWrite + Unpin>(
    dispatcher: &Arc<dyn Dispatcher>,
    session: StreamSession,
    config: &HttpServerConfig,
    inbound: &mut W,
    diagnostic_requested: bool,
) -> io::Result<BoxStream> {
    let connecting = timeout(config.connect_timeout, dispatcher.connect_tcp(session));
    let (connected, diagnostic) = if diagnostic_requested {
        capture_outbound_diagnostic(connecting).await
    } else {
        (connecting.await, None)
    };
    match connected {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            write_error_with_diagnostic(inbound, error.http_status(), diagnostic.as_ref()).await?;
            Err(dispatch_to_io(error))
        }
        Err(_) => {
            write_error_with_diagnostic(inbound, 504, diagnostic.as_ref()).await?;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP outbound connect timed out",
            ))
        }
    }
}

fn requests_measure_diagnostic(headers: &[(String, String)]) -> bool {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(MEASURE_DIAGNOSTIC_HEADER))
        .map(|(_, value)| value.as_str());
    matches!(
        (values.next(), values.next()),
        (Some(MEASURE_DIAGNOSTIC_REQUEST), None)
    )
}

async fn write_error<W: AsyncWrite + Unpin>(stream: &mut W, status: u16) -> io::Result<()> {
    write_error_with_diagnostic(stream, status, None).await
}

async fn write_auth_required<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    write_timed(stream, b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Vole\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", Duration::from_secs(10)).await
}

async fn write_error_with_diagnostic<W: AsyncWrite + Unpin>(
    stream: &mut W,
    status: u16,
    diagnostic: Option<&OutboundDiagnostic>,
) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Proxy Error",
    };
    let diagnostic = diagnostic.map(format_measure_diagnostic_header);
    let diagnostic = diagnostic.as_deref().map_or_else(String::new, |value| {
        format!("{MEASURE_DIAGNOSTIC_HEADER}: {value}\r\n")
    });
    write_timed(stream, format!("HTTP/1.1 {status} {reason}\r\n{diagnostic}Connection: close\r\nContent-Length: 0\r\n\r\n").as_bytes(), Duration::from_secs(10)).await
}

fn format_measure_diagnostic_header(diagnostic: &OutboundDiagnostic) -> String {
    debug_assert!(diagnostic.message().len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES);
    let error = URL_SAFE_NO_PAD.encode(diagnostic.message().as_bytes());
    let value = format!(
        "v1;stage={};kind={};error={error}",
        diagnostic.stage(),
        diagnostic.kind()
    );
    debug_assert!(value.len() <= MAX_MEASURE_DIAGNOSTIC_HEADER_BYTES);
    value
}

fn dispatch_to_io(error: DispatchError) -> io::Error {
    let kind = match error {
        DispatchError::NotAllowed => io::ErrorKind::PermissionDenied,
        DispatchError::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
        DispatchError::HostUnreachable => io::ErrorKind::HostUnreachable,
        DispatchError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        DispatchError::TimedOut => io::ErrorKind::TimedOut,
        DispatchError::Other(_) => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        dispatch::{BoxStream, DatagramTransport},
        outbound::EstablishContext,
        session::{DatagramSession, Destination},
    };

    const TEST_USERNAME: &str = "measure";
    const TEST_PASSWORD: &str = "secret";

    fn test_auth() -> HttpBasicAuth {
        HttpBasicAuth::new(TEST_USERNAME, TEST_PASSWORD).unwrap()
    }

    fn test_authorization() -> String {
        test_auth().authorization_header_value()
    }

    struct HttpTestDispatcher {
        request: Arc<Mutex<Vec<u8>>>,
    }

    struct FailingDispatcher {
        message: String,
    }

    #[async_trait]
    impl Dispatcher for HttpTestDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            let (client, mut remote) = tokio::io::duplex(8 * 1024);
            let recorded = self.request.clone();
            if session.destination == Destination::domain("example.com", 80).unwrap() {
                tokio::spawn(async move {
                    let mut input = Vec::new();
                    let mut byte = [0_u8; 1];
                    while remote.read_exact(&mut byte).await.is_ok() {
                        input.push(byte[0]);
                        if input.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    *recorded.lock().unwrap() = input;
                    let _ = remote
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            } else {
                tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(remote);
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::Other("unused".to_owned()))
        }
    }

    #[async_trait]
    impl Dispatcher for FailingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            let message = self.message.clone();
            EstablishContext::default()
                .run_io("VLESS TLS/REALITY handshake", async move {
                    Err::<(), _>(io::Error::new(io::ErrorKind::InvalidData, message))
                })
                .await?;
            unreachable!("the failing dispatcher never returns a stream")
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::Other("unused".to_owned()))
        }
    }

    async fn start_server() -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
        Arc<Mutex<Vec<u8>>>,
    ) {
        let request = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = Arc::new(HttpTestDispatcher {
            request: request.clone(),
        });
        let config =
            HttpServerConfig::loopback("127.0.0.1:0".parse().unwrap(), test_auth()).unwrap();
        let server = HttpServer::bind(config, dispatcher).await.unwrap();
        let address = server.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(server.serve(child));
        (address, cancellation, task, request)
    }

    async fn start_failing_server(
        message: String,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let config =
            HttpServerConfig::loopback("127.0.0.1:0".parse().unwrap(), test_auth()).unwrap();
        let server = HttpServer::bind(config, Arc::new(FailingDispatcher { message }))
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(server.serve(child));
        (address, cancellation, task)
    }

    #[test]
    fn basic_auth_validates_and_keeps_credentials_out_of_debug_output() {
        let auth = HttpBasicAuth::new("用户", "p:a:ss").unwrap();
        let value = auth.authorization_header_value();
        assert!(auth.verifies(&[(
            "Proxy-Authorization".to_owned(),
            value.replacen("Basic", "bAsIc", 1),
        )]));
        assert!(!auth.verifies(&[("Proxy-Authorization".to_owned(), "Basic !!!".to_owned(),)]));
        assert_eq!(format!("{auth:?}"), "ProxyCredentials { .. }");

        assert!(HttpBasicAuth::new("", "password").is_err());
        assert!(HttpBasicAuth::new("user", "").is_err());
        assert!(HttpBasicAuth::new("user:name", "password").is_err());
        assert!(HttpBasicAuth::new("u".repeat(255), "p".repeat(255)).is_ok());
        assert!(HttpBasicAuth::new("u".repeat(256), "password").is_err());
        assert!(HttpBasicAuth::new("user", "p".repeat(256)).is_err());
    }

    #[tokio::test]
    async fn missing_malformed_wrong_and_duplicate_auth_are_rejected_before_dispatch() {
        let (address, cancellation, task, _) = start_server().await;
        let valid = test_authorization();
        let wrong = HttpBasicAuth::new(TEST_USERNAME, "wrong")
            .unwrap()
            .authorization_header_value();
        for headers in [
            String::new(),
            "Proxy-Authorization: Bearer token\r\n".to_owned(),
            "Proxy-Authorization: Basic !!!\r\n".to_owned(),
            format!(
                "Proxy-Authorization: {wrong}\r\n{MEASURE_DIAGNOSTIC_HEADER}: {MEASURE_DIAGNOSTIC_REQUEST}\r\n"
            ),
            format!("Proxy-Authorization: {valid}\r\nProxy-Authorization: {valid}\r\n"),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(
                    format!(
                        "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n{headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Vole\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            );
        }

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn listener_keeps_accepting_beyond_the_former_connection_limit() {
        const HELD_CONNECTIONS: usize = 140;

        let (address, cancellation, task, _) = start_server().await;
        let mut held = Vec::with_capacity(HELD_CONNECTIONS);
        for _ in 0..HELD_CONNECTIONS {
            let mut client =
                tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(address))
                    .await
                    .expect("HTTP listener stopped accepting connections")
                    .unwrap();
            client.write_all(b"G").await.unwrap();
            held.push(client);
        }

        let mut probe = TcpStream::connect(address).await.unwrap();
        probe
            .write_all(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), probe.read_to_end(&mut response))
            .await
            .expect("a connection beyond the former limit was not handled")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"));

        cancellation.cancel();
        drop((held, probe));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_tunnels_early_and_late_data() {
        let (address, cancellation, task, _) = start_server().await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\nProxy-Authorization: {}\r\n\r\nearly",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let mut echoed = [0_u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"early");
        client.write_all(b"later").await.unwrap();
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"later");
        cancellation.cancel();
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn absolute_form_is_rewritten_and_proxy_headers_are_removed() {
        let (address, cancellation, task, request) = start_server().await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: stale\r\nProxy-Authorization: {}\r\nConnection: X-Drop\r\nX-Drop: yes\r\n\r\n",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        let forwarded = String::from_utf8(request.lock().unwrap().clone()).unwrap();
        assert!(forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(forwarded.contains("Host: example.com:80\r\n"));
        assert!(!forwarded.contains("Proxy-Authorization"));
        assert!(!forwarded.contains("X-Drop"));
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn origin_form_and_upgrade_without_host_are_rejected() {
        let (address, cancellation, task, _) = start_server().await;
        for request in [
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: {}\r\n\r\n",
                test_authorization()
            ),
            format!(
                "GET http://example.com/ HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Authorization: {}\r\n\r\n",
                test_authorization()
            ),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(request.as_bytes()).await.unwrap();
            let mut response = [0_u8; 64];
            let length = client.read(&mut response).await.unwrap();
            assert!(
                response[..length].starts_with(b"HTTP/1.1 4")
                    || response[..length].starts_with(b"HTTP/1.1 501")
            );
        }
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ordinary_connect_failure_keeps_the_compatible_plain_502_response() {
        let (address, cancellation, task) =
            start_failing_server("certificate rejected".to_owned()).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {}\r\n\r\n",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn diagnostic_is_disabled_for_shared_or_unauthenticated_listeners() {
        for shared in [false, true] {
            let config = HttpServerConfig::proxy(
                0,
                ProxyAccess {
                    bind_address: None,
                    allow_lan: shared,
                    ipv6: false,
                },
                shared.then(test_auth),
            )
            .unwrap();
            let server = HttpServer::bind(
                config,
                Arc::new(FailingDispatcher {
                    message: "fixture private diagnostic".to_owned(),
                }),
            )
            .await
            .unwrap();
            let port = server.local_addr().unwrap().port();
            let cancellation = CancellationToken::new();
            let task = tokio::spawn(server.serve(cancellation.clone()));
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            client.write_all(format!("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {}\r\n{MEASURE_DIAGNOSTIC_HEADER}: v1\r\n\r\n", test_authorization()).as_bytes()).await.unwrap();
            let mut response = String::new();
            timeout(Duration::from_secs(2), client.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 502"));
            assert!(!response.contains(MEASURE_DIAGNOSTIC_HEADER));
            assert!(!response.contains("fixture private"));
            cancellation.cancel();
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn opted_in_connect_failure_encodes_bounded_crlf_and_utf8_diagnostic() {
        let message = format!("证书失败\r\nInjected: yes {}", "界".repeat(100));
        let (address, cancellation, task) = start_failing_server(message).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {}\r\n{MEASURE_DIAGNOSTIC_HEADER}: {MEASURE_DIAGNOSTIC_REQUEST}\r\n\r\n",
                    test_authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(!response.contains("\r\nInjected: yes"));

        let header = response
            .split("\r\n")
            .find_map(|line| line.strip_prefix(&format!("{MEASURE_DIAGNOSTIC_HEADER}: ")))
            .unwrap();
        assert!(header.len() <= MAX_MEASURE_DIAGNOSTIC_HEADER_BYTES);
        assert!(header.starts_with("v1;stage=vless-security;kind=invalid_data;error="));
        let encoded = header.split_once(";error=").unwrap().1;
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let decoded = String::from_utf8(decoded).unwrap();
        assert!(decoded.starts_with("证书失败\r\nInjected: yes "));
        assert!(decoded.ends_with("..."));
        assert!(decoded.len() <= MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES);

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }
}
