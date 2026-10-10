//! Shared, bounded HTTP(S) health probes through the runtime dispatcher.
use crate::security::{SecurityContext, StandardTlsClient, TlsClientOptions};
use crate::{
    dispatch::{BoxStream, DispatchError, Dispatcher},
    inbound::DEFAULT_HEADER_LIMIT,
    outbound::{OutboundDiagnostic, capture_outbound_diagnostic},
    session::{Destination, InboundKind, StreamSession},
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetHost {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone)]
pub(crate) struct Target {
    scheme: TargetScheme,
    pub(crate) destination: Destination,
    pub(crate) authority: String,
    pub(crate) origin_form: String,
    tls_server_name: String,
}

impl Target {
    pub(crate) fn parse(raw: &str) -> io::Result<Self> {
        let url = Url::parse(raw).map_err(|_| invalid_input("url is not a valid absolute URL"))?;
        let scheme = match url.scheme() {
            "http" => TargetScheme::Http,
            "https" => TargetScheme::Https,
            _ => {
                return Err(invalid_input("url scheme must be http or https"));
            }
        };
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(invalid_input(
                "url must not contain authentication or a fragment",
            ));
        }
        let host = match url.host() {
            Some(Host::Domain(domain)) => {
                if domain.len() > u8::MAX as usize {
                    return Err(invalid_input("url host is too long"));
                }
                TargetHost::Domain(domain.to_owned())
            }
            Some(Host::Ipv4(address)) => TargetHost::Ip(IpAddr::V4(address)),
            Some(Host::Ipv6(address)) => TargetHost::Ip(IpAddr::V6(address)),
            None => return Err(invalid_input("url must contain a host")),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| invalid_input("url must contain a port"))?;
        let destination = match &host {
            TargetHost::Domain(domain) => {
                Destination::domain(domain.clone(), port).map_err(invalid_input)?
            }
            TargetHost::Ip(address) => Destination::Ip(SocketAddr::new(*address, port)),
        };
        let authority = authority(&host, port);
        let mut origin_form = url.path().to_owned();
        if origin_form.is_empty() {
            origin_form.push('/');
        }
        if let Some(query) = url.query() {
            origin_form.push('?');
            origin_form.push_str(query);
        }
        let tls_server_name = match &host {
            TargetHost::Domain(domain) => domain.clone(),
            TargetHost::Ip(address) => address.to_string(),
        };
        Ok(Self {
            scheme,
            destination,
            authority,
            origin_form,
            tls_server_name,
        })
    }
}

fn authority(host: &TargetHost, port: u16) -> String {
    match host {
        TargetHost::Domain(domain) => format!("{domain}:{port}"),
        TargetHost::Ip(IpAddr::V4(address)) => format!("{address}:{port}"),
        TargetHost::Ip(IpAddr::V6(address)) => format!("[{address}]:{port}"),
    }
}

async fn connect(
    target: &Target,
    dispatcher: Arc<dyn Dispatcher>,
    security: &SecurityContext,
) -> io::Result<BoxStream> {
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        destination: target.destination.clone(),
        sniffed_domain: None,
    };
    let (stream, diagnostic) = capture_outbound_diagnostic(dispatcher.connect_tcp(session)).await;
    let stream = stream.map_err(|error| outbound_connect_error(error, diagnostic.as_ref()))?;
    let stream = if target.scheme == TargetScheme::Https {
        let client = StandardTlsClient::with_options(
            security,
            &target.tls_server_name,
            TlsClientOptions {
                alpn: vec![b"http/1.1".to_vec()],
                ..Default::default()
            },
            0,
            64 * 1024,
        )?;
        connect_target_tls(&client, stream).await?
    } else {
        stream
    };
    Ok(stream)
}

fn outbound_connect_error(
    error: DispatchError,
    diagnostic: Option<&OutboundDiagnostic>,
) -> io::Error {
    let diagnostic = diagnostic.map_or_else(String::new, |diagnostic| {
        format!(
            " (Vole outbound stage={} kind={} error={:?})",
            diagnostic.stage(),
            diagnostic.kind(),
            diagnostic.message()
        )
    });
    io::Error::other(format!("outbound connect failed: {error}{diagnostic}"))
}

async fn connect_target_tls(
    connector: &StandardTlsClient,
    stream: BoxStream,
) -> io::Result<BoxStream> {
    connector
        .connect(stream)
        .await
        .map_err(|_| io::Error::other("probe TLS handshake failed"))
}

async fn head(stream: &mut BoxStream, target: &Target, keep_alive: bool) -> io::Result<u16> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    stream.write_all(format!("HEAD {} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: Vole/{}\r\nConnection: {connection}\r\n\r\n",target.origin_form,target.authority,env!("CARGO_PKG_VERSION")).as_bytes()).await?;
    stream.flush().await?;
    read_response_status(stream).await
}
#[cfg(test)]
pub(crate) async fn probe_once(
    target: &Target,
    dispatcher: Arc<dyn Dispatcher>,
    security: &SecurityContext,
) -> io::Result<()> {
    let mut stream = connect(target, dispatcher, security).await?;
    head(&mut stream, target, false).await.map(drop)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observation {
    pub delay: u64,
    pub expected_matches: bool,
}

pub(crate) async fn probe(
    target: &Target,
    dispatcher: Arc<dyn Dispatcher>,
    timeout: Duration,
    unified: bool,
    expected: &[(u16, u16)],
    cancel: &CancellationToken,
    security: &SecurityContext,
) -> io::Result<u64> {
    let observation = observe(
        target, dispatcher, timeout, unified, expected, cancel, security,
    )
    .await?;
    if observation.expected_matches {
        Ok(observation.delay)
    } else {
        Err(io::Error::other("unexpected health check status"))
    }
}

pub(crate) async fn observe(
    target: &Target,
    dispatcher: Arc<dyn Dispatcher>,
    timeout: Duration,
    unified: bool,
    expected: &[(u16, u16)],
    cancel: &CancellationToken,
    security: &SecurityContext,
) -> io::Result<Observation> {
    let operation = async {
        let mut started = Instant::now();
        let mut stream = connect(target, dispatcher, security).await?;
        let mut status = head(&mut stream, target, unified).await?;
        if unified {
            let second = Instant::now();
            if let Ok(next) = head(&mut stream, target, false).await {
                started = second;
                status = next;
            }
        }
        Ok(Observation {
            delay: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            expected_matches: expected.is_empty()
                || expected
                    .iter()
                    .any(|(start, end)| (*start..=*end).contains(&status)),
        })
    };
    tokio::select! {biased;
        ()=cancel.cancelled()=>Err(io::ErrorKind::Interrupted.into()),
        result=tokio::time::timeout(timeout,operation)=>result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut,"health check timed out"))?
    }
}
fn invalid_input(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

pub(crate) async fn read_response_status<R>(reader: &mut R) -> io::Result<u16>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    let mut input = Vec::with_capacity(1024);
    let mut total_read = 0_usize;
    loop {
        if let Some(end) = input.windows(4).position(|window| window == b"\r\n\r\n") {
            let status = parse_status(&input[..end])?;
            if (100..200).contains(&status) && status != 101 {
                input.drain(..end + 4);
                continue;
            }
            return Ok(status);
        }
        if total_read >= DEFAULT_HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP response heads exceed their aggregate limit",
            ));
        }
        let mut chunk = [0_u8; 1024];
        let remaining = DEFAULT_HEADER_LIMIT - total_read;
        let max_read = remaining.min(chunk.len());
        let length = reader.read(&mut chunk[..max_read]).await?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP connection closed before the response head",
            ));
        }
        total_read += length;
        input.extend_from_slice(&chunk[..length]);
    }
}

pub(crate) fn parse_status(head: &[u8]) -> io::Result<u16> {
    let line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(head.len());
    let line = &head[..line_end];
    let mut fields = line.splitn(3, |byte| *byte == b' ');
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if (version != b"HTTP/1.0" && version != b"HTTP/1.1")
        || status.len() != 3
        || !status.iter().all(u8::is_ascii_digit)
    {
        return Err(invalid_data("invalid HTTP response status line"));
    }
    let status = u16::from(status[0] - b'0') * 100
        + u16::from(status[1] - b'0') * 10
        + u16::from(status[2] - b'0');
    if !(100..=599).contains(&status) {
        return Err(invalid_data("HTTP response status is out of range"));
    }
    Ok(status)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dispatch::DatagramTransport, session::DatagramSession};
    use std::sync::Mutex;
    struct Memory(Mutex<Option<BoxStream>>);
    #[async_trait::async_trait]
    impl Dispatcher for Memory {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            Ok(self.0.lock().unwrap().take().unwrap())
        }
        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }
    #[tokio::test]
    async fn unified_probe_reuses_stream_checks_status_and_cancels() {
        let (client, mut server) = tokio::io::duplex(4096);
        let dispatcher = Arc::new(Memory(Mutex::new(Some(Box::new(client)))));
        let peer = tokio::spawn(async move {
            for _ in 0..2 {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(server.read_u8().await.unwrap());
                }
                assert!(head.starts_with(b"HEAD / HTTP/1.1"));
                server
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let cancel = CancellationToken::new();
        let target = Target::parse("http://example.test/").unwrap();
        probe(
            &target,
            dispatcher.clone(),
            Duration::from_secs(1),
            true,
            &[(204, 204)],
            &cancel,
            &SecurityContext::new(),
        )
        .await
        .unwrap();
        peer.await.unwrap();
        cancel.cancel();
        assert_eq!(
            probe(
                &target,
                dispatcher,
                Duration::from_secs(1),
                false,
                &[],
                &cancel,
                &SecurityContext::new(),
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
    }
}
