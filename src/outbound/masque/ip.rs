use super::{ConnectionFactory, datagram::Registry, packet, resolver};
use crate::{
    config::{MasqueNetwork, MasqueOutboundConfig},
    dispatch::DispatchError,
    dns::resolution::ResolutionContext,
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, EstablishContext},
    resources::observation,
    security::SecurityContext,
    session::{Destination, StreamSession},
    transport::{GrpcPool, h3_connect, masque_codec as codec},
};
use bytes::Bytes;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{
    ClientConfig, ClientNetStackParts, ClientPrefix, MAX_RECEIVE_PACKET_SIZE, NetStack,
    NetStackConfig, NetStackControl, Packet, PacketSink, PacketStream, TcpConnector,
};

const CONTROL_ENTRIES: usize = 8192;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ready {
    Pending,
    Open,
    Failed,
}

pub(super) struct Engine {
    pub config: Arc<MasqueOutboundConfig>,
    pub security: SecurityContext,
    pub resolution: ResolutionContext,
    pub remote: OnceLock<Arc<crate::dns::runtime::RuntimeDns>>,
    pub client: ClientConfig,
    pub mtu: usize,
    pub cancel: CancellationToken,
    pub tcp: TcpConnector,
    pub tx: mpsc::Sender<Packet>,
    pub registry: Arc<Registry>,
    ready: watch::Receiver<Ready>,
    control: NetStackControl,
    job: AsyncMutex<Option<JoinHandle<()>>>,
    stop: AsyncMutex<()>,
}
impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        config: Arc<MasqueOutboundConfig>,
        factory: Arc<ConnectionFactory>,
        pool: Arc<h3_connect::Pool>,
        h2_pool: Arc<GrpcPool>,
        security: SecurityContext,
        session: StreamSession,
        context: EstablishContext,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>, DispatchError> {
        let mtu = usize::try_from(config.mtu).map_err(|_| DispatchError::HostUnreachable)?;
        let client = ClientConfig {
            prefixes: config.local_prefixes.map(|prefix| {
                prefix.map(|(address, prefix_len)| ClientPrefix {
                    address,
                    prefix_len,
                })
            }),
            receive_packet_limit: MAX_RECEIVE_PACKET_SIZE,
            path_mtu_discovery: true,
        }
        .validate(mtu)
        .map_err(|_| DispatchError::Other("invalid MASQUE IP stack".into()))?;
        let ClientNetStackParts {
            packet_sink,
            packet_stream,
            tcp_connector,
            control,
            ..
        } = NetStack::start_client(
            NetStackConfig {
                mtu,
                packet_queue: 32,
                ..Default::default()
            },
            client,
        )
        .map_err(|_| DispatchError::Other("MASQUE IP stack initialization failed".into()))?;
        let (tx, output) = mpsc::channel(32);
        let (ready_sender, ready) = watch::channel(Ready::Pending);
        let registry = Arc::new(Registry::default());
        let engine = Arc::new(Self {
            config: config.clone(),
            security,
            resolution: context.resolution(),
            remote: OnceLock::new(),
            client,
            mtu,
            cancel: cancel.clone(),
            tcp: tcp_connector,
            tx,
            registry: registry.clone(),
            ready,
            control: control.clone(),
            job: AsyncMutex::new(None),
            stop: AsyncMutex::new(()),
        });
        // The worker owns endpoint handles, never its Engine Arc. Publication
        // precedes authentication, so Stop owns setup as well as packet I/O.
        *engine.job.try_lock().unwrap() = Some(observation::spawn(async move {
            let result = tokio::select! {biased;
                ()=cancel.cancelled()=>Err(closed()),
                result=run(config,factory,pool,h2_pool,session,context,client,packet_sink,packet_stream,output,registry,&ready_sender)=>result,
            };
            let _ = result;
            ready_sender.send_replace(Ready::Failed);
            cancel.cancel();
            control.stop().await;
        }));
        Ok(engine)
    }
    pub async fn wait_ready(&self, context: &EstablishContext) -> Result<(), DispatchError> {
        let mut ready = self.ready.clone();
        context.run("MASQUE IP handshake",async {
            loop {
                match *ready.borrow_and_update() {
                    Ready::Open=>return Ok(()),
                    Ready::Failed=>return Err(DispatchError::ConnectionRefused),
                    Ready::Pending=>{},
                }
                tokio::select! {biased;
                    ()=self.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
                    result=ready.changed()=>if result.is_err(){return Err(DispatchError::ConnectionRefused);},
                }
            }
        }).await
    }
    pub(super) fn initializing(&self) -> bool {
        *self.ready.borrow() == Ready::Pending
    }
    #[cfg(test)]
    pub(super) async fn job_is_joined(&self) -> bool {
        self.job.lock().await.is_none()
    }
    pub fn local(&self, destination: IpAddr) -> Result<IpAddr, DispatchError> {
        self.client
            .source_for(destination)
            .map_err(DispatchError::from)
    }
    pub async fn resolve(
        self: &Arc<Self>,
        target: &Destination,
        resolution: &ResolutionContext,
        deadline: Instant,
    ) -> Result<SocketAddr, DispatchError> {
        resolver::resolve_ip(self, target, resolution, deadline).await
    }
    pub async fn stop(&self) {
        let _stop = self.stop.lock().await;
        self.cancel.cancel();
        if let Some(remote) = self.remote.get() {
            remote.begin_shutdown();
            remote.shutdown().await;
        }
        let mut job = self.job.lock().await;
        if let Some(job) = job.as_mut() {
            let _ = job.await;
        }
        job.take();
        self.control.stop().await;
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.control.cancel();
        if let Some(remote) = self.remote.get() {
            remote.begin_shutdown();
        }
        if let Some(job) = self.job.get_mut().take() {
            job.abort();
        }
    }
}

fn h2_request(uri: &str) -> io::Result<http::Request<()>> {
    // Url normalizes explicit default ports away. Preserve the raw authority
    // so http://host:80 stays :80 while an omitted port always uses :443.
    let raw = uri
        .split_once("://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE URI"))?
        .1
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let raw = raw.rsplit('@').next().unwrap_or_default();
    let authority: http::uri::Authority = raw
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE authority"))?;
    let authority = if authority.port().is_some() {
        authority.to_string()
    } else {
        format!("{}:443", authority.host())
    };
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(
            http::Uri::builder()
                .authority(authority)
                .build()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE authority")
                })?,
        )
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE request"))
}

fn request(uri: &str) -> io::Result<http::Request<()>> {
    let mut url = url::Url::parse(uri)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE URI"))?;
    url.set_fragment(None);
    // URL userinfo is not an authority or an authentication header here.
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(url.as_str())
        .header("capsule-protocol", "?1")
        .header("user-agent", "")
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE request"))?;
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CF_CONNECT_IP);
    Ok(request)
}
fn routes() -> io::Result<Bytes> {
    let mut routes = Vec::with_capacity(44);
    routes.push(4);
    routes.extend_from_slice(&[0; 4]);
    routes.extend_from_slice(&[255; 4]);
    routes.push(0);
    routes.push(6);
    routes.extend_from_slice(&[0; 16]);
    routes.extend_from_slice(&[255; 16]);
    routes.push(0);
    codec::encode_capsule(codec::ROUTE_ADVERTISEMENT, &routes, MAX_RECEIVE_PACKET_SIZE)
}
#[allow(clippy::too_many_arguments)]
async fn run(
    config: Arc<MasqueOutboundConfig>,
    factory: Arc<ConnectionFactory>,
    pool: Arc<h3_connect::Pool>,
    h2_pool: Arc<GrpcPool>,
    session: StreamSession,
    context: EstablishContext,
    client: ClientConfig,
    sink: PacketSink,
    packets: PacketStream,
    output: mpsc::Receiver<Packet>,
    registry: Arc<Registry>,
    ready: &watch::Sender<Ready>,
) -> io::Result<()> {
    enum Tunnel {
        H2(crate::dispatch::BoxStream),
        H3(h3_connect::IpConnect),
    }
    let tunnel = tokio::time::timeout_at(context.deadline(), async {
        let setup = context.clone();
        if config.network == MasqueNetwork::H2 {
            let request = h2_request(&config.uri)?;
            let io = h2_pool
                .open_connect_admitted(request, context.deadline(), move || async move {
                    factory.connect_h2(session, &setup).await
                })
                .await?;
            return Ok(Tunnel::H2(io));
        }
        let request = request(&config.uri)?;
        let mut tunnel = pool
            .open_ip_connect(request, context.deadline(), move || async move {
                factory.connect(session, &setup).await
            })
            .await?;
        tunnel.capsules.write_all(&routes()?).await?;
        tunnel.capsules.flush().await?;
        if client.has_ipv6() {
            tunnel
                .datagrams
                .wait_packet_budget(1280, context.deadline())
                .await?;
        }
        Ok::<_, io::Error>(Tunnel::H3(tunnel))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if Instant::now() >= context.deadline() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    ready.send_replace(Ready::Open);
    match tunnel {
        Tunnel::H2(io) => {
            let (read, write) = tokio::io::split(io);
            tokio::try_join!(
                pump_h2_output(packets, output, write),
                pump_capsules(read, &sink, &registry, &client, true)
            )?;
        }
        Tunnel::H3(tunnel) => {
            tokio::try_join!(
                pump_output(packets, output, &tunnel.datagrams, &sink),
                pump_input(&tunnel.datagrams, &sink, &registry, &client),
                pump_capsules(tunnel.capsules, &sink, &registry, &client, false),
            )?;
        }
    }
    Err(closed())
}
async fn pump_h2_output<W: tokio::io::AsyncWrite + Unpin>(
    mut packets: PacketStream,
    mut udp: mpsc::Receiver<Packet>,
    mut writer: W,
) -> io::Result<()> {
    loop {
        let packet = tokio::select! {
            packet=packets.recv()=>packet.ok_or_else(closed)?,
            packet=udp.recv()=>packet.ok_or_else(closed)?,
        };
        if let Some(bytes) = packet::outgoing(packet.into_bytes()) {
            let capsule = codec::encode_capsule(codec::DATAGRAM, &bytes, MAX_RECEIVE_PACKET_SIZE)?;
            writer.write_all(&capsule).await?;
            writer.flush().await?;
        }
    }
}
async fn pump_output(
    mut packets: PacketStream,
    mut udp: mpsc::Receiver<Packet>,
    datagrams: &h3_connect::IpDatagrams,
    sink: &PacketSink,
) -> io::Result<()> {
    loop {
        let packet = tokio::select! {
            packet=packets.recv()=>packet.ok_or_else(closed)?,
            packet=udp.recv()=>packet.ok_or_else(closed)?,
        };
        let bytes = packet.into_bytes();
        let mut maximum = datagrams.packet_budget();
        if bytes.first().is_some_and(|first| first >> 4 == 6) && maximum < 1280 {
            maximum = datagrams
                .wait_packet_budget(1280, Instant::now() + DEFAULT_ESTABLISH_TIMEOUT)
                .await?;
        }
        if bytes.len() > maximum {
            if let Some(feedback) = vole_netstack::build_packet_too_big(&bytes, maximum) {
                sink.send(feedback).await.map_err(|_| closed())?;
            }
            continue;
        }
        if let Some(bytes) = packet::outgoing(bytes) {
            let deadline = Instant::now() + DEFAULT_ESTABLISH_TIMEOUT;
            loop {
                match datagrams.send(&bytes).await {
                    Ok(()) => break,
                    Err(h3_connect::IpDatagramSendError::TooLarge { packet_budget }) => {
                        if bytes.first().is_some_and(|first| first >> 4 == 6)
                            && packet_budget < 1280
                        {
                            datagrams.wait_packet_budget(1280, deadline).await?;
                            continue;
                        }
                        if let Some(feedback) =
                            vole_netstack::build_packet_too_big(&bytes, packet_budget)
                        {
                            sink.send(feedback).await.map_err(|_| closed())?;
                        }
                        break;
                    }
                    Err(h3_connect::IpDatagramSendError::Closed) => return Err(closed()),
                }
            }
        }
    }
}
async fn deliver(
    bytes: Bytes,
    sink: &PacketSink,
    registry: &Registry,
    client: &ClientConfig,
) -> io::Result<()> {
    if !packet::incoming(&bytes, client) {
        return Ok(());
    }
    if let Some(udp) = vole_netstack::parse_udp_packet_view(&bytes) {
        registry.deliver(udp.source, udp.destination, udp.payload);
    } else {
        sink.send(Packet::new(bytes)).await.map_err(|_| closed())?;
    }
    Ok(())
}
async fn pump_input(
    datagrams: &h3_connect::IpDatagrams,
    sink: &PacketSink,
    registry: &Registry,
    client: &ClientConfig,
) -> io::Result<()> {
    loop {
        deliver(datagrams.receive().await?, sink, registry, client).await?;
    }
}
async fn pump_capsules<R: tokio::io::AsyncRead + Unpin>(
    mut stream: R,
    sink: &PacketSink,
    registry: &Registry,
    client: &ClientConfig,
    h2: bool,
) -> io::Result<()> {
    let mut decoder = codec::CapsuleDecoder::new(MAX_RECEIVE_PACKET_SIZE);
    let mut chunk = [0u8; crate::transport::STREAM_CHUNK_BYTES];
    loop {
        let len = stream.read(&mut chunk).await?;
        if len == 0 {
            decoder.finish()?;
            return Err(closed());
        }
        let mut input = &chunk[..len];
        while !input.is_empty() {
            let (consumed, capsule) = decoder.feed(input)?;
            if consumed == 0 {
                return Err(closed());
            }
            input = &input[consumed..];
            let Some(capsule) = capsule else { continue };
            match capsule.kind {
                codec::DATAGRAM if h2 => deliver(capsule.value, sink, registry, client).await?,
                codec::ADDRESS_ASSIGN | codec::ADDRESS_REQUEST if !h2 => {
                    codec::parse_addresses(capsule.kind, &capsule.value, CONTROL_ENTRIES)?;
                }
                codec::ROUTE_ADVERTISEMENT if !h2 => {
                    codec::parse_routes(&capsule.value, CONTROL_ENTRIES)?;
                }
                _ => {}
            }
        }
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "MASQUE IP tunnel stopped")
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn test_config() -> Arc<MasqueOutboundConfig> {
        Arc::new(MasqueOutboundConfig {
            address: "example.invalid".into(),
            port: 443,
            private_key: String::new(),
            public_key: String::new(),
            server_name: "example.invalid".into(),
            network: MasqueNetwork::H2,
            ip: "192.0.2.2".into(),
            ipv6: String::new(),
            uri: "https://example.invalid".into(),
            mtu: 1280,
            udp: true,
            handshake_timeout: 0,
            skip_cert_verify: false,
            name_cert_verify: String::new(),
            congestion_controller: String::new(),
            cwnd: 0,
            bbr_profile: String::new(),
            ip_stack: crate::config::MasqueIpStackOptions {
                mode: "auto".into(),
                congestion_controller: String::new(),
            },
            remote_dns_resolve: false,
            dns: Vec::new(),
            local_prefixes: [Some((IpAddr::from([192, 0, 2, 2]), 32)), None],
        })
    }
    #[test]
    fn masque_ip_request_and_full_routes_use_cf_wire_contract() {
        let request = request("https://example.invalid:443/tunnel?x=1#ignored").unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/tunnel?x=1"
        );
        assert_eq!(request.headers()["capsule-protocol"], "?1");
        assert_eq!(
            request.extensions().get::<h3::ext::Protocol>(),
            Some(&h3::ext::Protocol::CF_CONNECT_IP)
        );
        let frame = routes().unwrap();
        let mut decoder = codec::CapsuleDecoder::new(256);
        let (_, capsule) = decoder.feed(&frame).unwrap();
        let routes = codec::parse_routes(&capsule.unwrap().value, 2).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| route.protocol == 0));
        assert_eq!(routes[0].start, IpAddr::from([0, 0, 0, 0]));
        assert_eq!(routes[0].end, IpAddr::from([255, 255, 255, 255]));
        assert!(routes[1].start.is_ipv6());
    }

    #[tokio::test]
    async fn masque_ip_cancelled_stop_keeps_the_join_barrier() {
        let client = ClientConfig {
            prefixes: [
                Some(ClientPrefix {
                    address: IpAddr::from([192, 0, 2, 2]),
                    prefix_len: 32,
                }),
                None,
            ],
            receive_packet_limit: MAX_RECEIVE_PACKET_SIZE,
            path_mtu_discovery: true,
        };
        let parts = NetStack::start_client(NetStackConfig::default(), client).unwrap();
        let (tx, _output) = mpsc::channel(1);
        let (_, ready) = watch::channel(Ready::Pending);
        let (release, work) = tokio::sync::oneshot::channel();
        let job = tokio::spawn(async move {
            let _ = work.await;
        });
        let engine = Engine {
            config: test_config(),
            security: SecurityContext::default(),
            resolution: ResolutionContext::default(),
            remote: OnceLock::new(),
            client,
            mtu: 1500,
            cancel: CancellationToken::new(),
            tcp: parts.tcp_connector,
            tx,
            registry: Arc::new(Registry::default()),
            ready,
            control: parts.control,
            job: AsyncMutex::new(Some(job)),
            stop: AsyncMutex::new(()),
        };
        let mut first = Box::pin(engine.stop());
        assert!(futures_util::poll!(first.as_mut()).is_pending());
        assert!(engine.cancel.is_cancelled());
        drop(first);
        assert!(engine.job.try_lock().unwrap().is_some());
        release.send(()).unwrap();
        engine.stop().await;
        assert!(engine.job.try_lock().unwrap().is_none());
    }

    #[test]
    fn masque_h2_authority_and_headers_preserve_mode_contract() {
        for (uri, authority) in [
            ("https://example.invalid/path?x=1", "example.invalid:443"),
            ("http://example.invalid:80/path", "example.invalid:80"),
            ("http://example.invalid/path", "example.invalid:443"),
            ("https://[2001:db8::1]/path", "[2001:db8::1]:443"),
        ] {
            let request = h2_request(uri).unwrap();
            assert_eq!(request.uri().authority().unwrap().as_str(), authority);
            assert!(request.uri().scheme().is_none());
            assert!(request.uri().path_and_query().is_none());
            assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
            assert_eq!(request.headers()["pq-enabled"], "false");
            assert!(request.headers().get("capsule-protocol").is_none());
            assert!(request.extensions().get::<h3::ext::Protocol>().is_none());
        }
    }
}
