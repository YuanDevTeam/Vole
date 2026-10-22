use std::{io, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    config::Socks5OutboundConfig,
    dialer::{Dialer, ResolvedEndpoint},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    security::{
        SecurityContext, StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsClientOptions,
    },
    session::{Datagram, DatagramSession, Destination, StreamSession},
    socks5::{
        COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, MAX_UDP_HEADER_SIZE, VERSION, decode_udp_packet,
        encode_address, encode_udp_packet, read_destination,
    },
};

use super::{
    ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    server_destination,
};

const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const USERNAME_PASSWORD_VERSION: u8 = 0x01;
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_NOT_ALLOWED: u8 = 0x02;
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_TTL_EXPIRED: u8 = 0x06;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Auth {
    username: String,
    password: String,
}

impl Socks5Auth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> io::Result<Self> {
        let username = username.into();
        let password = password.into();
        if !(1..=usize::from(u8::MAX)).contains(&username.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 username must contain between 1 and 255 UTF-8 bytes",
            ));
        }
        if !(1..=usize::from(u8::MAX)).contains(&password.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 password must contain between 1 and 255 UTF-8 bytes",
            ));
        }
        Ok(Self { username, password })
    }
}

#[derive(Clone)]
pub struct Socks5Outbound {
    server: Destination,
    auth: Option<Socks5Auth>,
    upstream: UpstreamPath,
    tls: Option<StandardTlsClient>,
}

impl std::fmt::Debug for Socks5Outbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Socks5Outbound")
            .field("server", &self.server)
            .field("has_auth", &self.auth.is_some())
            .field("tls", &self.tls.is_some())
            .field("upstream", &self.upstream)
            .finish()
    }
}

impl Socks5Outbound {
    pub fn new(
        config: &Socks5OutboundConfig,
        endpoint: ResolvedEndpoint,
        dialer: Dialer,
    ) -> io::Result<Self> {
        validate_endpoint(config, &endpoint)?;
        Self::new_with_path(config, UpstreamPath::direct(endpoint, dialer))
    }

    pub fn new_with_upstream(
        config: &Socks5OutboundConfig,
        upstream: Arc<dyn OutboundConnector>,
    ) -> io::Result<Self> {
        Self::new_with_path(config, UpstreamPath::proxy(upstream))
    }

    pub fn new_with_path(
        config: &Socks5OutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        let security = config.tls.as_ref().map(|_| SecurityContext::new());
        Self::with_shared_security(
            config,
            upstream,
            security.as_ref(),
            TLS_RESUMPTION_SESSION_BUDGET,
            64 * 1024,
        )
    }

    pub(crate) fn with_shared_security(
        config: &Socks5OutboundConfig,
        upstream: UpstreamPath,
        security: Option<&SecurityContext>,
        sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let auth = match (&config.username, &config.password) {
            (None, None) => None,
            (Some(username), Some(password)) => {
                Some(Socks5Auth::new(username.clone(), password.clone())?)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 username and password must be configured together",
                ));
            }
        };
        Ok(Self {
            server: server_destination(&config.address, config.port)?,
            auth,
            upstream,
            tls: config
                .tls
                .as_ref()
                .map(|policy| {
                    StandardTlsClient::with_options(
                        security.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "SOCKS5 TLS requires security context",
                            )
                        })?,
                        &config.address,
                        TlsClientOptions::from_policy(
                            policy,
                            None,
                            security.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "SOCKS5 TLS requires security context",
                                )
                            })?,
                        )?,
                        sessions,
                        buffer_limit,
                    )
                })
                .transpose()?,
        })
    }

    async fn connect_control(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let mut control = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?;
        if let Some(tls) = &self.tls {
            control.io = context
                .run_io("SOCKS5 TLS handshake", tls.connect(control.io))
                .await?;
        }
        Ok(control)
    }

    async fn establish_tcp(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let effective_peer = session.destination.clone();
        let mut control = self.connect_control(session.clone(), context).await?;
        context
            .run("SOCKS5 CONNECT handshake", async {
                negotiate_auth(&mut control.io, self.auth.as_ref()).await?;
                let _bound =
                    request(&mut control.io, COMMAND_CONNECT, &session.destination).await?;
                Ok(())
            })
            .await?;
        Ok(ConnectedStream {
            io: control.io,
            effective_peer,
        })
    }

    async fn establish_udp(
        &self,
        request_parameters: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let control_session = StreamSession {
            metadata: request_parameters.session.metadata.clone(),
            inbound: request_parameters.session.inbound,
            source: request_parameters.session.source,
            destination: self.server.clone(),
            sniffed_domain: None,
        };
        let mut control = self.connect_control(control_session, context).await?;
        let wildcard = Destination::Ip("0.0.0.0:0".parse().expect("valid wildcard address"));
        let relay = context
            .run("SOCKS5 UDP ASSOCIATE handshake", async {
                negotiate_auth(&mut control.io, self.auth.as_ref()).await?;
                request(&mut control.io, COMMAND_UDP_ASSOCIATE, &wildcard).await
            })
            .await?;
        let relay = normalize_udp_relay(
            relay,
            &control.effective_peer,
            &self.server,
            self.upstream.is_direct(context)?,
        )?;

        let relay = self.upstream.ip4p_datagram_relay(relay, context)?;

        let upstream_limit = request_parameters
            .max_response_payload_size()
            .saturating_add(MAX_UDP_HEADER_SIZE);
        let upstream_request = request_parameters.with_envelope(
            usize::from(MAX_UDP_HEADER_SIZE),
            usize::from(MAX_UDP_HEADER_SIZE),
        );
        let inner = self
            .upstream
            .open_datagram(upstream_request, context)
            .await?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(Socks5DatagramTransport {
                control: control.io,
                inner,
                relay,
                max_response_payload_size: usize::from(
                    request_parameters.max_response_payload_size(),
                ),
                max_wire_response_size: usize::from(upstream_limit),
            }),
            request_parameters.budget(),
        ))
    }
}

#[async_trait]
impl OutboundConnector for Socks5Outbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.establish_tcp(session, context).await
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.establish_udp(request, context).await
    }
}

#[async_trait]
impl Dispatcher for Socks5Outbound {
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

async fn negotiate_auth(
    stream: &mut BoxStream,
    auth: Option<&Socks5Auth>,
) -> Result<(), DispatchError> {
    let offered = if auth.is_some() {
        AUTH_USERNAME_PASSWORD
    } else {
        AUTH_NO_AUTH
    };
    stream.write_all(&[VERSION, 1, offered]).await?;
    stream.flush().await?;
    let mut selection = [0_u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != VERSION {
        return Err(protocol_error("SOCKS5 server selected an invalid version"));
    }
    if selection[1] == AUTH_NO_ACCEPTABLE_METHODS {
        return Err(DispatchError::NotAllowed);
    }
    if selection[1] != offered {
        return Err(protocol_error(
            "SOCKS5 server selected an authentication method that was not offered",
        ));
    }

    if let Some(auth) = auth {
        let username_length =
            u8::try_from(auth.username.len()).expect("validated SOCKS5 username length fits u8");
        let password_length =
            u8::try_from(auth.password.len()).expect("validated SOCKS5 password length fits u8");
        let mut request = Vec::with_capacity(3 + auth.username.len() + auth.password.len());
        request.extend_from_slice(&[USERNAME_PASSWORD_VERSION, username_length]);
        request.extend_from_slice(auth.username.as_bytes());
        request.push(password_length);
        request.extend_from_slice(auth.password.as_bytes());
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != USERNAME_PASSWORD_VERSION {
            return Err(protocol_error(
                "SOCKS5 username/password response has an invalid version",
            ));
        }
        if response[1] != 0 {
            return Err(DispatchError::NotAllowed);
        }
    }
    Ok(())
}

async fn request(
    stream: &mut BoxStream,
    command: u8,
    destination: &Destination,
) -> Result<Destination, DispatchError> {
    let mut request = Vec::with_capacity(3 + usize::from(MAX_UDP_HEADER_SIZE));
    request.extend_from_slice(&[VERSION, command, 0]);
    encode_address(destination, &mut request).map_err(DispatchError::from)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = [0_u8; 3];
    stream.read_exact(&mut response).await?;
    if response[0] != VERSION || response[2] != 0 {
        return Err(protocol_error("invalid SOCKS5 response header"));
    }
    let bound = read_destination(stream, true).await?;
    match response[1] {
        REPLY_SUCCEEDED => Ok(bound),
        REPLY_NOT_ALLOWED => Err(DispatchError::NotAllowed),
        REPLY_NETWORK_UNREACHABLE => Err(DispatchError::NetworkUnreachable),
        REPLY_HOST_UNREACHABLE => Err(DispatchError::HostUnreachable),
        REPLY_CONNECTION_REFUSED => Err(DispatchError::ConnectionRefused),
        REPLY_TTL_EXPIRED => Err(DispatchError::TimedOut),
        reply => Err(DispatchError::Other(format!(
            "SOCKS5 server rejected the request with reply {reply:#04x}"
        ))),
    }
}

fn normalize_udp_relay(
    relay: Destination,
    control_peer: &Destination,
    server: &Destination,
    direct: bool,
) -> Result<Destination, DispatchError> {
    if relay.port() == 0 {
        return Err(protocol_error("SOCKS5 UDP relay port is zero"));
    }
    let port = relay.port();
    match relay {
        Destination::Ip(address) if address.ip().is_unspecified() => {
            replace_destination_port(control_peer, port)
        }
        Destination::Domain { host, .. } if direct => {
            let same_server = matches!(
                server,
                Destination::Domain { host: server_host, .. }
                    if server_host.eq_ignore_ascii_case(&host)
            );
            if !same_server {
                return Err(DispatchError::HostUnreachable);
            }
            match control_peer {
                Destination::Ip(_) => replace_destination_port(control_peer, port),
                Destination::Domain { .. } => Err(DispatchError::HostUnreachable),
            }
        }
        relay => Ok(relay),
    }
}

fn replace_destination_port(
    destination: &Destination,
    port: u16,
) -> Result<Destination, DispatchError> {
    match destination {
        Destination::Ip(address) => Ok(Destination::Ip(std::net::SocketAddr::new(
            address.ip(),
            port,
        ))),
        Destination::Domain { host, .. } => {
            Destination::domain(host.clone(), port).map_err(DispatchError::from)
        }
    }
}

fn validate_endpoint(config: &Socks5OutboundConfig, endpoint: &ResolvedEndpoint) -> io::Result<()> {
    if endpoint.logical_host != config.address
        || endpoint.port != config.port
        || endpoint.addresses.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolved endpoint does not match the configured SOCKS5 server",
        ));
    }
    Ok(())
}

fn protocol_error(message: impl Into<String>) -> DispatchError {
    DispatchError::Other(message.into())
}

struct Socks5DatagramTransport {
    control: BoxStream,
    inner: Box<dyn DatagramTransport>,
    relay: Destination,
    max_response_payload_size: usize,
    max_wire_response_size: usize,
}

#[async_trait]
impl DatagramTransport for Socks5DatagramTransport {
    fn supports_shared_destinations(&self) -> bool {
        true
    }

    fn payload_budget(&self, peer: &Destination) -> crate::dispatch::DatagramBudget {
        let Ok(address) = crate::socks5::encoded_address_size(peer) else {
            return crate::dispatch::DatagramBudget::new(0, 0);
        };
        let transmit = address + 3;
        let receive = if matches!(peer, Destination::Domain { .. }) {
            usize::from(MAX_UDP_HEADER_SIZE)
        } else {
            transmit
        };
        self.inner
            .payload_budget(&self.relay)
            .subtract_overhead(transmit, receive)
            .intersect(crate::dispatch::DatagramBudget::new(
                u16::MAX,
                self.max_response_payload_size as u16,
            ))
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        let packet = encode_udp_packet(&datagram.remote, &datagram.payload, usize::from(u16::MAX))
            .map_err(|error| protocol_error(format!("invalid SOCKS5 UDP request: {error}")))?;
        self.inner
            .send(Datagram {
                remote: self.relay.clone(),
                payload: Bytes::from(packet),
                sniffed_domain: None,
            })
            .await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            let mut unexpected_control_data = [0_u8; 1];
            tokio::select! {
                biased;
                control = self.control.read(&mut unexpected_control_data) => {
                    match control {
                        Ok(0) => return Err(protocol_error("SOCKS5 UDP control connection closed")),
                        Ok(_) => return Err(protocol_error("SOCKS5 UDP control connection produced unexpected data")),
                        Err(error) => return Err(DispatchError::from(error)),
                    }
                }
                received = self.inner.receive() => {
                    let received = received?;
                    if !relay_source_matches(&self.relay, &received.remote) {
                        continue;
                    }
                    let (remote, payload) = decode_udp_packet(
                        &received.payload,
                        self.max_wire_response_size,
                    )
                    .map_err(|error| protocol_error(format!("invalid SOCKS5 UDP response: {error}")))?;
                    if payload.len() > self.max_response_payload_size {
                        continue;
                    }
                    return Ok(Datagram {
                        remote,
                        payload: Bytes::copy_from_slice(payload),
                        sniffed_domain: None,
                    });
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        let inner = self.inner.close().await;
        let control = self.control.shutdown().await.map_err(DispatchError::from);
        inner.and(control)
    }
}

fn relay_source_matches(expected: &Destination, actual: &Destination) -> bool {
    match (expected, actual) {
        (Destination::Ip(_), _) => expected == actual,
        (
            Destination::Domain {
                host: expected_host,
                port: expected_port,
            },
            Destination::Domain {
                host: actual_host,
                port: actual_port,
            },
        ) => expected_port == actual_port && expected_host.eq_ignore_ascii_case(actual_host),
        (Destination::Domain { port, .. }, Destination::Ip(address)) => *port == address.port(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            Mutex,
            atomic::{AtomicU16, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;

    #[derive(Clone)]
    struct MockUpstream {
        command: u8,
        auth: Option<(String, String)>,
        relay: Destination,
        close_control: bool,
        fragment_response: bool,
        opened_limit: Arc<AtomicU16>,
        associates: Arc<AtomicUsize>,
        udp_opens: Arc<AtomicUsize>,
        switch_after_handshake: Option<Arc<crate::routing::GroupSelection>>,
    }

    impl MockUpstream {
        fn new(command: u8) -> Self {
            Self {
                command,
                auth: None,
                relay: Destination::Ip("192.0.2.2:53000".parse().unwrap()),
                close_control: false,
                fragment_response: false,
                opened_limit: Arc::new(AtomicU16::new(0)),
                associates: Arc::new(AtomicUsize::new(0)),
                udp_opens: Arc::new(AtomicUsize::new(0)),
                switch_after_handshake: None,
            }
        }
    }

    #[async_trait]
    impl OutboundConnector for MockUpstream {
        async fn connect_stream(
            &self,
            session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            assert_eq!(session.destination.port(), 1080);
            let (client, mut server) = tokio::io::duplex(4 * 1024);
            let command = self.command;
            let auth = self.auth.clone();
            let relay = self.relay.clone();
            let close_control = self.close_control;
            let associates = self.associates.clone();
            let switch_after_handshake = self.switch_after_handshake.clone();
            tokio::spawn(async move {
                let mut greeting = [0_u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting[..2], [VERSION, 1]);
                let method = if auth.is_some() {
                    AUTH_USERNAME_PASSWORD
                } else {
                    AUTH_NO_AUTH
                };
                assert_eq!(greeting[2], method);
                server.write_all(&[VERSION, method]).await.unwrap();

                if let Some((username, password)) = auth {
                    assert_eq!(server.read_u8().await.unwrap(), USERNAME_PASSWORD_VERSION);
                    let username_length = usize::from(server.read_u8().await.unwrap());
                    let mut received_username = vec![0_u8; username_length];
                    server.read_exact(&mut received_username).await.unwrap();
                    let password_length = usize::from(server.read_u8().await.unwrap());
                    let mut received_password = vec![0_u8; password_length];
                    server.read_exact(&mut received_password).await.unwrap();
                    assert_eq!(received_username, username.as_bytes());
                    assert_eq!(received_password, password.as_bytes());
                    server
                        .write_all(&[USERNAME_PASSWORD_VERSION, 0])
                        .await
                        .unwrap();
                }

                let mut header = [0_u8; 3];
                server.read_exact(&mut header).await.unwrap();
                assert_eq!(header, [VERSION, command, 0]);
                let destination = read_destination(&mut server, command == COMMAND_UDP_ASSOCIATE)
                    .await
                    .unwrap();
                if command == COMMAND_UDP_ASSOCIATE {
                    assert_eq!(destination.port(), 0);
                    associates.fetch_add(1, Ordering::Relaxed);
                } else {
                    assert_eq!(
                        destination,
                        Destination::domain("target.example", 443).unwrap()
                    );
                }

                let mut response = vec![VERSION, REPLY_SUCCEEDED, 0];
                if let Some(selection) = switch_after_handshake {
                    selection.store(1, Ordering::Release);
                }
                encode_address(&relay, &mut response).unwrap();
                server.write_all(&response).await.unwrap();
                server.flush().await.unwrap();
                if close_control {
                    return;
                }
                if command == COMMAND_CONNECT {
                    let mut buffer = [0_u8; 32];
                    loop {
                        let read = server.read(&mut buffer).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        server.write_all(&buffer[..read]).await.unwrap();
                    }
                } else {
                    // TCP control EOF ends the fixture along with the association.
                    let _ = server.read_u8().await;
                }
            });
            Ok(ConnectedStream {
                io: Box::new(client),
                effective_peer: Destination::Ip("192.0.2.1:1080".parse().unwrap()),
            })
        }

        async fn open_datagram(
            &self,
            request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_opens.fetch_add(1, Ordering::Relaxed);
            self.opened_limit
                .store(request.max_response_payload_size(), Ordering::Relaxed);
            Ok(Box::new(MockDatagrams {
                responses: Mutex::new(VecDeque::new()),
                fragment_response: self.fragment_response,
            }))
        }
    }

    struct MockDatagrams {
        responses: Mutex<VecDeque<Datagram>>,
        fragment_response: bool,
    }

    struct NestedSocksUpstream {
        connection_index: AtomicUsize,
        opened_limit: AtomicU16,
    }

    impl NestedSocksUpstream {
        fn new() -> Self {
            Self {
                connection_index: AtomicUsize::new(0),
                opened_limit: AtomicU16::new(0),
            }
        }
    }

    #[async_trait]
    impl OutboundConnector for NestedSocksUpstream {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            let index = self.connection_index.fetch_add(1, Ordering::Relaxed);
            let (client, mut server) = tokio::io::duplex(8 * 1024);
            tokio::spawn(async move {
                match index {
                    0 => {
                        serve_no_auth_request(
                            &mut server,
                            COMMAND_CONNECT,
                            Destination::Ip("192.0.2.10:41000".parse().unwrap()),
                        )
                        .await;
                        // The outer SOCKS CONNECT now acts as a transparent
                        // stream to the inner SOCKS server.
                        serve_no_auth_request(
                            &mut server,
                            COMMAND_UDP_ASSOCIATE,
                            Destination::Ip("0.0.0.0:54000".parse().unwrap()),
                        )
                        .await;
                    }
                    1 => {
                        serve_no_auth_request(
                            &mut server,
                            COMMAND_UDP_ASSOCIATE,
                            Destination::Ip("192.0.2.20:55000".parse().unwrap()),
                        )
                        .await;
                    }
                    _ => panic!("unexpected nested SOCKS control connection {index}"),
                }
                pending::<()>().await;
            });
            Ok(ConnectedStream {
                io: Box::new(client),
                effective_peer: Destination::Ip("192.0.2.1:1080".parse().unwrap()),
            })
        }

        async fn open_datagram(
            &self,
            request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.opened_limit
                .store(request.max_response_payload_size(), Ordering::Relaxed);
            Ok(Box::new(MockDatagrams {
                responses: Mutex::new(VecDeque::new()),
                fragment_response: false,
            }))
        }
    }

    async fn serve_no_auth_request(
        stream: &mut tokio::io::DuplexStream,
        expected_command: u8,
        bound: Destination,
    ) {
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [VERSION, 1, AUTH_NO_AUTH]);
        stream.write_all(&[VERSION, AUTH_NO_AUTH]).await.unwrap();

        let mut header = [0_u8; 3];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [VERSION, expected_command, 0]);
        let destination = read_destination(stream, expected_command == COMMAND_UDP_ASSOCIATE)
            .await
            .unwrap();
        if expected_command == COMMAND_CONNECT {
            assert_eq!(
                destination,
                Destination::domain("inner.example", 1080).unwrap()
            );
        } else {
            assert_eq!(destination.port(), 0);
        }

        let mut response = vec![VERSION, REPLY_SUCCEEDED, 0];
        encode_address(&bound, &mut response).unwrap();
        stream.write_all(&response).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[async_trait]
    impl DatagramTransport for MockDatagrams {
        fn supports_shared_destinations(&self) -> bool {
            false
        }

        async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
            if self.fragment_response {
                let mut payload = datagram.payload.to_vec();
                payload[2] = 1;
                datagram.payload = Bytes::from(payload);
            }
            self.responses.lock().unwrap().push_back(datagram);
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if let Some(response) = self.responses.lock().unwrap().pop_front() {
                return Ok(response);
            }
            pending().await
        }
    }

    fn config(auth: Option<(&str, &str)>) -> Socks5OutboundConfig {
        Socks5OutboundConfig {
            tls: None,
            address: "socks.example".to_owned(),
            port: 1080,
            username: auth.map(|(username, _)| username.to_owned()),
            password: auth.map(|(_, password)| password.to_owned()),
        }
    }

    fn stream_session() -> StreamSession {
        StreamSession {
            metadata: Default::default(),
            inbound: crate::session::InboundKind::Http,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::domain("target.example", 443).unwrap(),
            sniffed_domain: None,
        }
    }

    fn datagram_request() -> DatagramRequest {
        DatagramRequest::new(DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        ))
    }

    #[test]
    fn auth_requires_non_empty_bounded_utf8_fields() {
        assert!(Socks5Auth::new("user", "password").is_ok());
        assert!(Socks5Auth::new("", "password").is_err());
        assert!(Socks5Auth::new("user", "").is_err());
        assert!(Socks5Auth::new("u".repeat(256), "password").is_err());
        assert!(Socks5Auth::new("user", "p".repeat(256)).is_err());
    }

    #[tokio::test]
    async fn tcp_connect_supports_no_auth_and_username_password() {
        for credentials in [None, Some(("user", "password"))] {
            let mut upstream = MockUpstream::new(COMMAND_CONNECT);
            upstream.auth =
                credentials.map(|(username, password)| (username.to_owned(), password.to_owned()));
            let outbound =
                Socks5Outbound::new_with_upstream(&config(credentials), Arc::new(upstream))
                    .unwrap();
            let mut connected = OutboundConnector::connect_stream(
                &outbound,
                stream_session(),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
            assert_eq!(
                connected.effective_peer,
                Destination::domain("target.example", 443).unwrap()
            );
            connected.io.write_all(b"ping").await.unwrap();
            connected.io.flush().await.unwrap();
            let mut echoed = [0_u8; 4];
            connected.io.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"ping");
        }
    }

    #[tokio::test]
    async fn udp_associate_round_trips_domain_and_ipv6_and_widens_wire_limit() {
        let upstream = MockUpstream::new(COMMAND_UDP_ASSOCIATE);
        let opened_limit = upstream.opened_limit.clone();
        let outbound =
            Socks5Outbound::new_with_upstream(&config(None), Arc::new(upstream)).unwrap();
        let mut transport = OutboundConnector::open_datagram(
            &outbound,
            datagram_request(),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        assert_eq!(opened_limit.load(Ordering::Relaxed), 1_714);

        for destination in [
            Destination::domain("target.example", 53).unwrap(),
            Destination::Ip("[2001:db8::1]:53".parse().unwrap()),
        ] {
            transport
                .send(Datagram {
                    remote: destination.clone(),
                    payload: Bytes::from_static(b"query"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            let response = transport.receive().await.unwrap();
            assert_eq!(response.remote, destination);
            assert_eq!(&response.payload[..], b"query");
        }
    }

    #[tokio::test]
    async fn managed_udp_shares_socks_association_and_isolates_closed_members() {
        use crate::{
            connections::Registry,
            dispatch::observe_sessions_with_stats,
            outbound::{ConnectorDispatcher, RejectOutbound},
            resources::RuntimeResourceStats,
            routing::{
                EmptyGeoMatcher, ProxyDispatchers, RoutingDispatcher, RuleSet,
                diagnostics::Diagnostics,
            },
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            let upstream = MockUpstream::new(COMMAND_UDP_ASSOCIATE);
            let associates = upstream.associates.clone();
            let udp_opens = upstream.udp_opens.clone();
            let opens = || {
                (
                    associates.load(Ordering::Relaxed),
                    udp_opens.load(Ordering::Relaxed),
                )
            };
            let node = Arc::new(
                Socks5Outbound::new_with_upstream(&config(None), Arc::new(upstream)).unwrap(),
            );
            let leaf = observe_sessions_with_stats(
                Arc::new(ConnectorDispatcher::new(node)),
                RuntimeResourceStats::new("socks_managed_memory"),
            );
            let parsed = crate::config::Config::parse_yaml(
                br#"
proxies: [{name: edge, type: socks5, server: socks.example, port: 1080, udp: true}]
rules: ["MATCH,edge"]
"#,
            )
            .unwrap();
            let rules = RuleSet::compile(parsed.rules.clone()).unwrap();
            let registry = Arc::new(Registry::default());
            let diagnostics = Arc::new(Diagnostics::new(&parsed, &rules, registry.clone()));
            let router = RoutingDispatcher::new(
                ProxyDispatchers::new(vec![leaf]).unwrap(),
                Arc::new(ConnectorDispatcher::new(Arc::new(
                    RejectOutbound::drop_connections(),
                ))),
                None,
                rules,
                Arc::new(EmptyGeoMatcher),
            )
            .with_diagnostics(diagnostics);
            let mut first = router
                .open_datagram(DatagramSession::for_tun(
                    "127.0.0.1:10000".parse().unwrap(),
                    1500,
                ))
                .await
                .unwrap();
            let mut second = router
                .open_datagram(DatagramSession::for_tun(
                    "127.0.0.1:10001".parse().unwrap(),
                    1500,
                ))
                .await
                .unwrap();
            let a: std::net::SocketAddr = "198.51.100.1:443".parse().unwrap();
            let b: std::net::SocketAddr = "198.51.100.2:53".parse().unwrap();
            let packet = |remote: std::net::SocketAddr, body: &'static [u8]| Datagram {
                remote: Destination::Ip(remote),
                payload: Bytes::from_static(body),
                sniffed_domain: None,
            };
            first.send(packet(a, b"stale")).await.unwrap();
            first.send(packet(b, b"sibling")).await.unwrap();
            assert_eq!(opens(), (1, 1), "same-source targets share one wire");
            second.send(packet(a, b"separate")).await.unwrap();
            assert_eq!(opens(), (2, 2), "different sources keep independent wires");

            let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
            let closed = snapshot["connections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| {
                    entry["metadata"]["sourcePort"] == "10000"
                        && entry["metadata"]["destinationIP"] == "198.51.100.1"
                        && entry["metadata"]["destinationPort"] == "443"
                })
                .unwrap();
            registry.close(closed["id"].as_str().unwrap());
            first.send(packet(a, b"fresh")).await.unwrap();
            assert_eq!(opens(), (3, 3), "recreated target needs a new wire");

            // Both old replies remain queued: the retired wire must deliver
            // its sibling's frame while isolating the closed target's reply.
            let mut replies = std::collections::HashMap::new();
            for _ in 0..2 {
                let reply = first.receive().await.unwrap();
                assert!(replies.insert(reply.remote, reply.payload).is_none());
            }
            assert_eq!(replies[&Destination::Ip(a)].as_ref(), b"fresh");
            assert_eq!(replies[&Destination::Ip(b)].as_ref(), b"sibling");
            let reply = second.receive().await.unwrap();
            assert_eq!(reply.remote, Destination::Ip(a));
            assert_eq!(reply.payload.as_ref(), b"separate");
            first.close().await.unwrap();
            second.close().await.unwrap();
            assert!(
                serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        })
        .await
        .expect("managed SOCKS memory IO must not wait on network or shutdown");
    }

    #[tokio::test]
    async fn group_switch_during_udp_handshake_keeps_control_and_relay_on_one_upstream() {
        use crate::outbound::{SelectUpstream, SelectUpstreamMember};

        let selection = Arc::new(crate::routing::GroupSelection::new(0));
        let mut first = MockUpstream::new(COMMAND_UDP_ASSOCIATE);
        first.switch_after_handshake = Some(selection.clone());
        let first_budget = first.opened_limit.clone();
        let second = MockUpstream::new(COMMAND_UDP_ASSOCIATE);
        let second_budget = second.opened_limit.clone();
        let child = Arc::new(SelectUpstream::new(
            selection.clone(),
            vec![
                SelectUpstreamMember::Proxy(Arc::new(first)),
                SelectUpstreamMember::Proxy(Arc::new(second)),
                SelectUpstreamMember::Reject,
            ],
        ));
        let group = Arc::new(SelectUpstream::new(
            Arc::new(crate::routing::GroupSelection::new(0)),
            vec![SelectUpstreamMember::Group(child)],
        ));
        let outbound = Socks5Outbound::new_with_path(
            &config(None),
            UpstreamPath::Group {
                server: crate::session::Destination::domain("server.example", 443).unwrap(),
                group,
                endpoint: None,
                dialer: Dialer::default(),
            },
        )
        .unwrap();
        let mut old = OutboundConnector::open_datagram(
            &outbound,
            datagram_request(),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        assert_eq!(selection.load(Ordering::Acquire), 1);
        assert_eq!(first_budget.load(Ordering::Relaxed), 1714);
        assert_eq!(second_budget.load(Ordering::Relaxed), 0);
        let mut new = OutboundConnector::open_datagram(
            &outbound,
            datagram_request(),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        assert_eq!(second_budget.load(Ordering::Relaxed), 1714);
        selection.store(2, Ordering::Release);
        assert!(matches!(
            OutboundConnector::open_datagram(
                &outbound,
                datagram_request(),
                &EstablishContext::default()
            )
            .await,
            Err(DispatchError::NotAllowed)
        ));
        // No migration of already established associations after a switch.
        for transport in [&mut old, &mut new] {
            transport
                .send(Datagram {
                    remote: Destination::domain("target.example", 53).unwrap(),
                    payload: Bytes::from_static(b"query"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(
                transport.receive().await.unwrap().payload.as_ref(),
                b"query"
            );
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn udp_control_eof_terminates_the_association() {
        let mut upstream = MockUpstream::new(COMMAND_UDP_ASSOCIATE);
        upstream.close_control = true;
        let outbound =
            Socks5Outbound::new_with_upstream(&config(None), Arc::new(upstream)).unwrap();
        let mut transport = OutboundConnector::open_datagram(
            &outbound,
            datagram_request(),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), transport.receive())
            .await
            .expect("control EOF must wake receive")
            .unwrap_err();
        assert!(error.to_string().contains("control connection closed"));
    }

    #[tokio::test]
    async fn udp_control_eof_wins_over_a_queued_relay_response() {
        let relay = Destination::Ip("192.0.2.2:53000".parse().unwrap());
        let remote = Destination::domain("target.example", 53).unwrap();
        let response = encode_udp_packet(&remote, b"stale", 1_714).unwrap();
        let (control, control_peer) = tokio::io::duplex(64);
        drop(control_peer);
        let mut transport = Socks5DatagramTransport {
            control: Box::new(control),
            inner: Box::new(MockDatagrams {
                responses: Mutex::new(VecDeque::from([Datagram {
                    remote: relay.clone(),
                    payload: Bytes::from(response),
                    sniffed_domain: None,
                }])),
                fragment_response: false,
            }),
            relay,
            max_response_payload_size: 1_452,
            max_wire_response_size: 1_714,
        };

        let error = transport.receive().await.unwrap_err();
        assert!(error.to_string().contains("control connection closed"));
    }

    #[tokio::test]
    async fn udp_fragmented_response_is_rejected() {
        let mut upstream = MockUpstream::new(COMMAND_UDP_ASSOCIATE);
        upstream.fragment_response = true;
        let outbound =
            Socks5Outbound::new_with_upstream(&config(None), Arc::new(upstream)).unwrap();
        let mut transport = OutboundConnector::open_datagram(
            &outbound,
            datagram_request(),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        transport
            .send(Datagram {
                remote: Destination::domain("target.example", 53).unwrap(),
                payload: Bytes::from_static(b"query"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        let error = transport.receive().await.unwrap_err();
        assert!(error.to_string().contains("fragmented"));
    }

    #[tokio::test]
    async fn socks_over_socks_udp_nests_control_relay_and_wire_budgets() {
        let physical = Arc::new(NestedSocksUpstream::new());
        let outer_config = Socks5OutboundConfig {
            tls: None,
            address: "outer.example".to_owned(),
            port: 1080,
            username: None,
            password: None,
        };
        let outer =
            Arc::new(Socks5Outbound::new_with_upstream(&outer_config, physical.clone()).unwrap());
        let inner_config = Socks5OutboundConfig {
            tls: None,
            address: "inner.example".to_owned(),
            port: 1080,
            username: None,
            password: None,
        };
        let inner = Socks5Outbound::new_with_upstream(&inner_config, outer).unwrap();

        let mut transport = OutboundConnector::open_datagram(
            &inner,
            datagram_request(),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        assert_eq!(physical.connection_index.load(Ordering::Relaxed), 2);
        assert_eq!(physical.opened_limit.load(Ordering::Relaxed), 1_976);

        let destination = Destination::domain("target.example", 53).unwrap();
        transport
            .send(Datagram {
                remote: destination.clone(),
                payload: Bytes::from_static(b"nested"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        let response = transport.receive().await.unwrap();
        assert_eq!(response.remote, destination);
        assert_eq!(&response.payload[..], b"nested");
    }

    #[tokio::test]
    async fn decoded_udp_payload_ceiling_drops_oversize_without_truncation() {
        let relay = Destination::Ip("192.0.2.2:53000".parse().unwrap());
        let remote = Destination::domain("target.example", 53).unwrap();
        let oversized = encode_udp_packet(&remote, &[7_u8; 1_453], 1_714).unwrap();
        let allowed = encode_udp_packet(&remote, b"ok", 1_714).unwrap();
        let responses = VecDeque::from([
            Datagram {
                remote: relay.clone(),
                payload: Bytes::from(oversized),
                sniffed_domain: None,
            },
            Datagram {
                remote: relay.clone(),
                payload: Bytes::from(allowed),
                sniffed_domain: None,
            },
        ]);
        let (control, control_peer) = tokio::io::duplex(64);
        tokio::spawn(async move {
            pending::<()>().await;
            drop(control_peer);
        });
        let mut transport = Socks5DatagramTransport {
            control: Box::new(control),
            inner: Box::new(MockDatagrams {
                responses: Mutex::new(responses),
                fragment_response: false,
            }),
            relay,
            max_response_payload_size: 1_452,
            max_wire_response_size: 1_714,
        };

        let response = transport.receive().await.unwrap();
        assert_eq!(response.remote, remote);
        assert_eq!(&response.payload[..], b"ok");
    }

    #[test]
    fn wildcard_relay_uses_the_effective_control_peer() {
        let relay = Destination::Ip("0.0.0.0:53000".parse().unwrap());
        let peer = Destination::Ip("192.0.2.1:1080".parse().unwrap());
        let server = Destination::domain("socks.example", 1080).unwrap();
        assert_eq!(
            normalize_udp_relay(relay, &peer, &server, true).unwrap(),
            Destination::Ip("192.0.2.1:53000".parse().unwrap())
        );
    }

    #[test]
    fn nested_wire_limit_adds_one_maximum_socks_header() {
        let request = DatagramRequest::new(DatagramSession::new(
            crate::session::InboundKind::Tun,
            "127.0.0.1:10000".parse().unwrap(),
        ));
        assert_eq!(
            request
                .max_response_payload_size()
                .saturating_add(MAX_UDP_HEADER_SIZE),
            1_714
        );
        assert_eq!(u16::MAX.saturating_add(MAX_UDP_HEADER_SIZE), u16::MAX);
    }

    #[test]
    fn direct_mode_rejects_an_unprepared_relay_domain() {
        let relay = Destination::domain("relay.example", 53000).unwrap();
        let peer = Destination::Ip("192.0.2.1:1080".parse().unwrap());
        let server = Destination::domain("socks.example", 1080).unwrap();
        assert!(normalize_udp_relay(relay, &peer, &server, true).is_err());
    }

    #[test]
    fn proxy_mode_keeps_a_domain_relay_for_remote_resolution() {
        let relay = Destination::domain("relay.example", 53000).unwrap();
        let peer = Destination::domain("socks.example", 1080).unwrap();
        let server = peer.clone();
        assert_eq!(
            normalize_udp_relay(relay.clone(), &peer, &server, false).unwrap(),
            relay
        );
    }

    #[test]
    fn domain_relay_accepts_remote_resolution_but_keeps_the_relay_port_locked() {
        let relay = Destination::domain("relay.example", 53_000).unwrap();
        assert!(relay_source_matches(
            &relay,
            &Destination::Ip("192.0.2.2:53000".parse().unwrap())
        ));
        assert!(relay_source_matches(
            &relay,
            &Destination::domain("RELAY.EXAMPLE", 53_000).unwrap()
        ));
        assert!(!relay_source_matches(
            &relay,
            &Destination::Ip("192.0.2.2:53001".parse().unwrap())
        ));
        assert!(!relay_source_matches(
            &relay,
            &Destination::domain("other.example", 53_000).unwrap()
        ));
    }
    #[test]
    fn ip4p_udp_relay_source_check_uses_the_actual_endpoint() {
        let encoded: std::net::SocketAddr = "[2001:0::1bb:c000:201]:8443".parse().unwrap();
        let dialer = Dialer::default().with_connections(crate::config::ConnectionSettings {
            dialer_ip4p_convert: true,
            ..Default::default()
        });
        let path = UpstreamPath::direct(
            ResolvedEndpoint {
                logical_host: encoded.ip().to_string(),
                port: 8443,
                addresses: vec![encoded],
            },
            dialer,
        );
        let expected = path
            .ip4p_datagram_relay(Destination::Ip(encoded), &EstablishContext::default())
            .unwrap();
        assert!(relay_source_matches(
            &expected,
            &Destination::Ip("192.0.2.1:443".parse().unwrap())
        ));
        assert!(!relay_source_matches(&expected, &Destination::Ip(encoded)));
        assert!(!relay_source_matches(
            &expected,
            &Destination::Ip("192.0.2.2:443".parse().unwrap())
        ));
    }
}
