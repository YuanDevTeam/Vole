use super::{ConnectionFactory, datagram::Registry, packet};
use crate::{
    config::MasqueOutboundConfig,
    dispatch::DispatchError,
    dns::resolution::ResolutionContext,
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, EstablishContext},
    resources::observation,
    session::{Destination, StreamSession},
    transport::{h3_connect, masque_codec as codec},
};
use bytes::Bytes;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
    pub fn start(
        config: Arc<MasqueOutboundConfig>,
        factory: Arc<ConnectionFactory>,
        pool: Arc<h3_connect::Pool>,
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
                result=run(config,factory,pool,session,context,client,packet_sink,packet_stream,output,registry,&ready_sender)=>result,
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
    pub fn local(&self, destination: IpAddr) -> Result<IpAddr, DispatchError> {
        self.client
            .source_for(destination)
            .map_err(DispatchError::from)
    }
    pub async fn resolve(
        &self,
        target: &Destination,
        resolution: &ResolutionContext,
        deadline: Instant,
    ) -> Result<SocketAddr, DispatchError> {
        resolution
            .resolve_local_family(
                target,
                deadline,
                self.client
                    .prefixes()
                    .any(|prefix| prefix.address.is_ipv4()),
                self.client.has_ipv6(),
            )
            .await
    }
    pub async fn stop(&self) {
        let _stop = self.stop.lock().await;
        self.cancel.cancel();
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
        if let Some(job) = self.job.get_mut().take() {
            job.abort();
        }
    }
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
    session: StreamSession,
    context: EstablishContext,
    client: ClientConfig,
    sink: PacketSink,
    packets: PacketStream,
    output: mpsc::Receiver<Packet>,
    registry: Arc<Registry>,
    ready: &watch::Sender<Ready>,
) -> io::Result<()> {
    let request = request(&config.uri)?;
    let setup = context.clone();
    let mut tunnel = pool
        .open_ip_connect(request, context.deadline(), move || async move {
            factory.connect(session, &setup).await
        })
        .await?;
    tunnel.capsules.write_all(&routes()?).await?;
    tunnel.capsules.flush().await?;
    if client.has_ipv6() {
        // QUIC starts at the reference's 1242-byte UDP payload. A declared
        // IPv6 path must demonstrate that a 1280-byte IP packet fits before
        // publishing the stack, rather than dropping its first full segment.
        tunnel
            .datagrams
            .wait_packet_budget(1280, context.deadline())
            .await?;
    }
    ready.send_replace(Ready::Open);
    tokio::try_join!(
        pump_output(packets, output, &tunnel.datagrams, &sink),
        pump_input(&tunnel.datagrams, &sink, &registry, &client),
        pump_capsules(tunnel.capsules, &sink, &registry, &client),
    )?;
    Err(closed())
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
async fn pump_capsules(
    mut stream: crate::dispatch::BoxStream,
    sink: &PacketSink,
    registry: &Registry,
    client: &ClientConfig,
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
                codec::DATAGRAM => {
                    let (context, len) =
                        codec::decode_varint(&capsule.value)?.ok_or_else(closed)?;
                    if context == 0 {
                        deliver(capsule.value.slice(len..), sink, registry, client).await?;
                    }
                }
                codec::ADDRESS_ASSIGN | codec::ADDRESS_REQUEST => {
                    codec::parse_addresses(capsule.kind, &capsule.value, CONTROL_ENTRIES)?;
                }
                codec::ROUTE_ADVERTISEMENT => {
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
mod tests {
    use super::*;
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
}
