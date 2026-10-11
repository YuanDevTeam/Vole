//! Cloudflare MASQUE CONNECT-IP and L4 CONNECT over controlled transports.
mod datagram;
mod ip;
mod packet;
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
use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) struct ConnectionFactory {
    server: Destination,
    server_name: String,
    upstream: UpstreamPath,
    tls: MasqueTls,
}
impl ConnectionFactory {
    pub(super) async fn connect(
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
    pool: Arc<h3_connect::Pool>,
    config: Arc<MasqueOutboundConfig>,
    current: AsyncMutex<Option<Arc<ip::Engine>>>,
    cancel: CancellationToken,
    admission: Mutex<()>,
    retired: TaskTracker,
}
impl MasqueOutbound {
    pub(crate) fn with_shared_security(
        config: &MasqueOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
    ) -> io::Result<Self> {
        if config.network == MasqueNetwork::H2 {
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
        let congestion = quic::congestion_controller(
            &config.congestion_controller,
            config.cwnd,
            &config.bbr_profile,
        );
        let pool = if config.network == MasqueNetwork::H3L4Proxy {
            h3_connect::Pool::masque_l4(congestion)
        } else {
            h3_connect::Pool::masque_ip(congestion)
        };
        Ok(Self {
            connection: Arc::new(ConnectionFactory {
                server: server_destination(&config.address, config.port)?,
                server_name: config.server_name.clone(),
                upstream,
                tls,
            }),
            pool: Arc::new(pool),
            config: Arc::new(config.clone()),
            current: AsyncMutex::new(None),
            cancel: CancellationToken::new(),
            admission: Mutex::new(()),
            retired: TaskTracker::new(),
        })
    }
    async fn engine(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<Arc<ip::Engine>, DispatchError> {
        let engine = tokio::select! { biased;
            ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
            result=context.run("MASQUE IP initialize",async {
                let mut current=self.current.lock().await;
                let _admission=self.admission.lock().unwrap();
                if self.cancel.is_cancelled() { return Err(DispatchError::NotAllowed); }
                if let Some(engine)=current.as_ref().filter(|engine|!engine.cancel.is_cancelled()) {return Ok(engine.clone());}
                if let Some(old)=current.take() {self.retired.spawn(crate::resources::observation::task(async move{old.stop().await;}));}
                let engine=ip::Engine::start(self.config.clone(),self.connection.clone(),self.pool.clone(),session,context.clone(),self.cancel.child_token())?;
                *current=Some(engine.clone());
                Ok(engine)
            })=>result?,
        };
        engine.wait_ready(context).await?;
        Ok(engine)
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
        if self.config.network != MasqueNetwork::H3L4Proxy {
            let engine = self.engine(session.clone(), context).await?;
            let remote = engine
                .resolve(
                    &session.destination,
                    &context.resolution(),
                    context.deadline(),
                )
                .await?;
            let io = tokio::select! {biased;
                ()=engine.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
                result=context.run_io("MASQUE IP TCP",engine.tcp.connect(remote,context.deadline()))=>result?,
            };
            return Ok(ConnectedStream {
                io: Box::new(crate::outbound::owned_stream::OwnedStream::new(
                    Box::new(io),
                    engine.cancel.child_token(),
                )),
                effective_peer: Destination::Ip(remote),
            });
        }
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
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if self.config.network == MasqueNetwork::H3L4Proxy || !self.config.udp {
            return Err(DispatchError::NotAllowed);
        }
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: self.connection.server.clone(),
            sniffed_domain: None,
        };
        let engine = self.engine(session, context).await?;
        Ok(Box::new(datagram::Datagrams::new(
            engine,
            request.budget(),
            context.resolution(),
        )?))
    }
    fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.retired.close();
        self.pool.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.retired.wait().await;
        let mut current = self.current.lock().await;
        if let Some(engine) = current.as_ref() {
            engine.stop().await;
        }
        current.take();
        self.pool.shutdown().await;
    }
}
impl Drop for MasqueOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.pool.begin_shutdown();
    }
}
