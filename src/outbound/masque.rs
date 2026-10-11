//! Cloudflare MASQUE L4 CONNECT over the shared controlled QUIC path.
use crate::{
    config::{MasqueNetwork, MasqueOutboundConfig},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    security::{SecurityContext, masque::MasqueTls},
    session::{DatagramSession, Destination, StreamSession},
    transport::{h3_connect, quic},
};
use async_trait::async_trait;
use std::{io, sync::Arc};

struct ConnectionFactory {
    server: Destination,
    server_name: String,
    upstream: UpstreamPath,
    tls: MasqueTls,
}
impl ConnectionFactory {
    async fn connect(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<h3_connect::QuicTransport> {
        let server = self
            .upstream
            .datagram_server(&self.server, context)
            .await
            .map_err(io::Error::other)?;
        let peer = context
            .resolve_ip(&server)
            .await
            .map_err(io::Error::other)?;
        let budget = DatagramBudget::new(1400, 1400);
        let request = DatagramRequest::new(
            DatagramSession::new(session.inbound, session.source).with_metadata(session.metadata),
        )
        .with_budget(budget);
        let transport = self
            .upstream
            .open_datagram(request, context)
            .await
            .map_err(io::Error::other)?;
        Ok(h3_connect::QuicTransport {
            transport,
            peer,
            budget,
            tls: self.tls.config(true)?,
            server_name: self.server_name.clone(),
        })
    }
}

pub struct MasqueOutbound {
    connection: Arc<ConnectionFactory>,
    pool: h3_connect::Pool,
}
impl MasqueOutbound {
    pub(crate) fn with_shared_security(
        config: &MasqueOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
    ) -> io::Result<Self> {
        if config.network != MasqueNetwork::H3L4Proxy {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "MASQUE IP mode is not implemented",
            ));
        }
        let tls = MasqueTls::new(
            &config.private_key,
            &config.public_key,
            config.skip_cert_verify,
            security,
        )?;
        let pool = h3_connect::Pool::masque_l4(quic::congestion_controller(
            &config.congestion_controller,
            config.cwnd,
            &config.bbr_profile,
        ));
        Ok(Self {
            connection: Arc::new(ConnectionFactory {
                server: server_destination(&config.address, config.port)?,
                server_name: config.server_name.clone(),
                upstream,
                tls,
            }),
            pool,
        })
    }
}

fn connect_request(target: &Destination) -> io::Result<http::Request<()>> {
    let authority = match target {
        Destination::Ip(address) => address.to_string(),
        Destination::Domain { host, port } => format!("{host}:{port}"),
    };
    let uri = http::Uri::builder()
        .authority(authority)
        .build()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid MASQUE CONNECT authority",
            )
        })?;
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .body(())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid MASQUE CONNECT request",
            )
        })
}

#[async_trait]
impl OutboundConnector for MasqueOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        // Mihomo resolves L4 business names locally unless node DNS is enabled;
        // endpoint bootstrap always retains the separate proxy-DNS role.
        let remote = context
            .resolution()
            .resolve_local_family(&session.destination, context.deadline(), true, true)
            .await?;
        let target = Destination::Ip(remote);
        let request = connect_request(&target)?;
        let factory = self.connection.clone();
        let setup = context.clone();
        let io = context
            .run_io(
                "MASQUE L4 CONNECT",
                self.pool
                    .open_connect(request, context.deadline(), None, move || async move {
                        factory.connect(session, &setup).await
                    }),
            )
            .await?;
        Ok(ConnectedStream {
            io,
            effective_peer: target,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    fn begin_shutdown(&self) {
        self.pool.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.pool.shutdown().await;
    }
}
