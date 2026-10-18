use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};

use crate::dialer::PhysicalDatagram as UdpSocket;
use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    dialer::Dialer,
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{Datagram, DatagramSession, Destination, StreamSession},
};

use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};

/// Built-in DIRECT action. Domain destinations must be resolved and pinned by
/// the routing layer before they reach this dispatcher.
#[derive(Debug, Clone)]
pub struct DirectOutbound {
    dialer: Dialer,
}

impl DirectOutbound {
    #[must_use]
    pub const fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

#[async_trait]
impl Dispatcher for DirectOutbound {
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

#[async_trait]
impl OutboundConnector for DirectOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let Destination::Ip(address) = session.destination else {
            return Err(DispatchError::HostUnreachable);
        };
        let stream = context
            .run_io("direct TCP connect", self.dialer.connect_address(address))
            .await?;
        let effective_peer = Destination::Ip(stream.peer_addr().map_err(DispatchError::from)?);
        Ok(ConnectedStream {
            io: Box::new(stream),
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        request: DatagramRequest,
        _context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(crate::dispatch::bound_datagram(
            Box::new(DirectDatagramTransport::new(
                self.dialer.clone(),
                usize::from(request.max_response_payload_size()),
                request.udp_socket_options(),
            )),
            request.budget(),
        ))
    }
}

struct DirectDatagramTransport {
    dialer: Dialer,
    sockets: Vec<(UdpSocketClass, Arc<UdpSocket>)>,
    max_response_payload_size: usize,
    socket_options: crate::dialer::UdpSocketOptions,
    receive_buffer: Vec<u8>,
    receive_cursor: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpSocketClass {
    ipv6: bool,
    loopback: bool,
}

impl DirectDatagramTransport {
    fn new(
        dialer: Dialer,
        max_response_payload_size: usize,
        socket_options: crate::dialer::UdpSocketOptions,
    ) -> Self {
        Self {
            dialer,
            sockets: Vec::with_capacity(4),
            max_response_payload_size,
            socket_options,
            receive_buffer: Vec::new(),
            receive_cursor: 0,
        }
    }

    async fn socket_for(&mut self, address: SocketAddr) -> Result<&UdpSocket, DispatchError> {
        let class = UdpSocketClass {
            ipv6: address.is_ipv6(),
            loopback: address.ip().is_loopback(),
        };
        if let Some(index) = self.sockets.iter().position(|(key, _)| *key == class) {
            return Ok(&self.sockets[index].1);
        }
        let socket = self
            .dialer
            .bind_udp_for_with_options(address, self.socket_options)
            .await
            .map_err(DispatchError::from)?;
        self.sockets.push((class, Arc::new(socket)));
        Ok(&self
            .sockets
            .last()
            .expect("direct UDP socket was inserted")
            .1)
    }

    async fn send_on(
        socket: &UdpSocket,
        payload: &[u8],
        address: SocketAddr,
    ) -> Result<(), DispatchError> {
        let written = socket
            .send_to(payload, address)
            .await
            .map_err(DispatchError::from)?;
        if written != payload.len() {
            return Err(DispatchError::Other(
                "direct UDP socket truncated a datagram".to_owned(),
            ));
        }
        Ok(())
    }

    fn poll_sockets(
        sockets: &[(UdpSocketClass, Arc<UdpSocket>)],
        max_payload: usize,
        cursor: &mut usize,
        context: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        if sockets.is_empty() {
            return Poll::Ready(Err(DispatchError::Other(
                "direct UDP receive requested before the first datagram".to_owned(),
            )));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            let mut retry = false;
            for offset in 0..sockets.len() {
                let index = (*cursor + offset) % sockets.len();
                let socket = &sockets[index].1;
                match socket.poll_recv_ready(context) {
                    Poll::Pending => continue,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(())) => {}
                }
                // Allocate only once a socket is readable. The extra byte
                // detects oversized datagrams rather than delivering a prefix.
                let required = max_payload + 1;
                if scratch.len() < required {
                    scratch.reserve_exact(required - scratch.len());
                    scratch.resize(required, 0);
                }
                match socket.try_recv_from(&mut scratch[..required]) {
                    Ok((length, remote)) if length <= max_payload => {
                        *cursor = (index + 1) % sockets.len();
                        return Poll::Ready(Ok(Datagram {
                            remote: Destination::Ip(remote),
                            payload: Bytes::copy_from_slice(&scratch[..length]),
                            sniffed_domain: None,
                        }));
                    }
                    Ok(_) => retry = true,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => retry = true,
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            }
            if !retry {
                return Poll::Pending;
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

#[async_trait]
impl DatagramTransport for DirectDatagramTransport {
    fn payload_budget(&self, peer: &Destination) -> crate::dispatch::DatagramBudget {
        let wire_limit = if matches!(peer, Destination::Ip(address) if address.is_ipv6()) {
            65_527
        } else {
            65_507
        };
        crate::dispatch::DatagramBudget::new(
            wire_limit,
            (self.max_response_payload_size as u16).min(wire_limit),
        )
    }

    fn send_owned(
        &mut self,
        datagram: Datagram,
    ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
        let Destination::Ip(address) = &datagram.remote else {
            return Err(datagram);
        };
        let address = *address;
        let class = UdpSocketClass {
            ipv6: address.is_ipv6(),
            loopback: address.ip().is_loopback(),
        };
        let Some((_, socket)) = self.sockets.iter().find(|(key, _)| *key == class) else {
            // The first ordinary send owns protected initialization.
            return Err(datagram);
        };
        let socket = socket.clone();
        Ok(Box::pin(async move {
            Self::send_on(&socket, &datagram.payload, address).await
        }))
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        let Destination::Ip(address) = datagram.remote else {
            return Err(DispatchError::HostUnreachable);
        };
        let socket = self.socket_for(address).await?;
        Self::send_on(socket, &datagram.payload, address).await
    }

    fn supports_poll_receive(&self) -> bool {
        true
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        Self::poll_sockets(
            &self.sockets,
            self.max_response_payload_size,
            &mut self.receive_cursor,
            context,
            scratch,
        )
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::poll_fn(|context| {
            Self::poll_sockets(
                &self.sockets,
                self.max_response_payload_size,
                &mut self.receive_cursor,
                context,
                &mut self.receive_buffer,
            )
        })
        .await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.sockets.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::net::{TcpListener, UdpSocket};

    use super::*;
    #[cfg(unix)]
    use crate::dialer::SocketProtector;
    use crate::session::InboundKind;

    #[cfg(unix)]
    struct CountingProtector(AtomicUsize);

    #[cfg(unix)]
    impl SocketProtector for CountingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn direct_tcp_connects_to_a_pinned_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let outbound = DirectOutbound::new(Dialer::default());
        let session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Http,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::Ip(destination),
            sniffed_domain: None,
        };
        let (_stream, accepted) = tokio::join!(outbound.connect_tcp(session), listener.accept());
        assert!(accepted.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn direct_udp_round_trips_and_protects_the_socket() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = echo.local_addr().unwrap();
        let protector = Arc::new(CountingProtector(AtomicUsize::new(0)));
        let outbound = DirectOutbound::new(Dialer::default().with_protector(protector.clone()));
        let session = DatagramSession::new(InboundKind::Http, "127.0.0.1:10000".parse().unwrap());
        let mut transport = Dispatcher::open_datagram(&outbound, session).await.unwrap();
        transport
            .send(Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"ping"),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        let mut received = [0_u8; 16];
        let (length, peer) = echo.recv_from(&mut received).await.unwrap();
        echo.send_to(&received[..length], peer).await.unwrap();
        let reply = transport.receive().await.unwrap();
        assert_eq!(reply.remote, Destination::Ip(destination));
        assert_eq!(&reply.payload[..], b"ping");
        assert_eq!(protector.0.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn direct_udp_drops_an_oversized_response_without_truncating_it() {
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = remote.local_addr().unwrap();
        let mut transport = DirectDatagramTransport::new(Dialer::default(), 4, Default::default());
        transport
            .send(Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"open"),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        let mut request = [0_u8; 16];
        let (_, peer) = remote.recv_from(&mut request).await.unwrap();
        remote.send_to(b"large", peer).await.unwrap();
        remote.send_to(b"good", peer).await.unwrap();

        let response = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive())
            .await
            .expect("valid response behind oversized datagram timed out")
            .unwrap();
        assert_eq!(response.remote, Destination::Ip(destination));
        assert_eq!(&response.payload[..], b"good");
        assert_eq!(transport.receive_buffer.len(), 5);
    }
}
