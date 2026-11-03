//! Framing peers use bounded in-memory IO; no DNS, sockets or server processes.
use super::{
    MieruOutbound, crypto,
    wire::{
        DataKind, DataMetadata, Metadata, Padding, SessionKind, SessionMetadata, StreamDecoder,
        StreamEncoder,
    },
};
use crate::{
    config::{MieruHandshake, MieruMultiplexing, MieruOutboundConfig, MieruTransport},
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    },
    resources::observation::{self, ResourceProbe},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
    socks5,
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::Notify,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) fn unix() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs())
}
pub(super) fn config(mode: MieruHandshake) -> MieruOutboundConfig {
    MieruOutboundConfig {
        address: "memory.invalid".into(),
        port: 2000,
        port_end: 2002,
        username: "vole".into(),
        password: "fixture-password".into(),
        transport: MieruTransport::Tcp,
        udp: true,
        multiplexing: MieruMultiplexing::High,
        handshake_mode: mode,
        traffic_pattern: None,
    }
}
pub(super) fn session() -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::Socks5,
        source: "192.0.2.10:1000".parse().unwrap(),
        destination: Destination::Ip("203.0.113.20:80".parse().unwrap()),
        sniffed_domain: None,
    }
}
pub(super) struct Peer {
    pub calls: AtomicUsize,
    stall: bool,
    cancel: CancellationToken,
    tasks: TaskTracker,
    ports: Mutex<Vec<u16>>,
    pub started: Notify,
}
impl Peer {
    pub fn new(stall: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            stall,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            ports: Mutex::new(Vec::new()),
            started: Notify::new(),
        })
    }
    pub async fn stop(&self) {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}
struct PeerSession {
    sequence: u32,
    request: Vec<u8>,
    ready: bool,
}
#[async_trait]
impl OutboundConnector for Peer {
    async fn connect_stream(
        &self,
        request: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.ports.lock().unwrap().push(request.destination.port());
        let (client, server) = tokio::io::duplex(if self.stall { 8 } else { 128 });
        let cancel = self.cancel.clone();
        let stall = self.stall;
        self.tasks.spawn(observation::task(async move {
            let serving = async {
                if stall {
                    let _server = server;
                    std::future::pending::<()>().await;
                } else {
                    let _ = serve(server).await;
                }
            };
            tokio::select! {biased;()=cancel.cancelled()=>{},()=serving=>{}}
        }));
        self.started.notify_one();
        Ok(ConnectedStream {
            io: Box::new(client),
            effective_peer: request.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
async fn send(
    stream: &mut DuplexStream,
    encoder: &mut StreamEncoder,
    metadata: Metadata,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> io::Result<()> {
    encoder.encode_frame(
        metadata,
        payload,
        Padding {
            prefix: &[],
            suffix: &[],
        },
        unix()?,
        output,
    )?;
    stream.write_all(output).await?;
    stream.flush().await
}
async fn data(
    stream: &mut DuplexStream,
    encoder: &mut StreamEncoder,
    id: u32,
    state: &mut PeerSession,
    bytes: &[u8],
    output: &mut Vec<u8>,
) -> io::Result<()> {
    for chunk in bytes.chunks(32768) {
        send(
            stream,
            encoder,
            Metadata::Data(DataMetadata {
                kind: DataKind::ServerData,
                session_id: id,
                sequence: state.sequence,
                unack_sequence: 0,
                window: 16,
                fragment: 0,
            }),
            chunk,
            output,
        )
        .await?;
        state.sequence = state.sequence.wrapping_add(1);
    }
    Ok(())
}
async fn serve(mut stream: DuplexStream) -> io::Result<()> {
    let key = Arc::new(crypto::derive_key("vole", "fixture-password", unix()?));
    let mut decoder = StreamDecoder::new(key.clone());
    let mut encoder = StreamEncoder::new(key, crypto::make_client_nonce("vole", rand::random()));
    let mut output = Vec::new();
    let mut sessions = HashMap::<u32, PeerSession>::new();
    while let Some(frame) = decoder.read_frame_with_clock(&mut stream, unix).await? {
        let id = match frame.metadata {
            Metadata::Session(meta) => meta.session_id,
            Metadata::Data(meta) => meta.session_id,
        };
        if let Metadata::Session(meta) = frame.metadata {
            if meta.kind == SessionKind::OpenRequest {
                assert_ne!(id, 0);
                assert!(!sessions.contains_key(&id));
                sessions.insert(
                    id,
                    PeerSession {
                        sequence: 1,
                        request: Vec::new(),
                        ready: false,
                    },
                );
                send(
                    &mut stream,
                    &mut encoder,
                    Metadata::Session(SessionMetadata {
                        kind: SessionKind::OpenResponse,
                        session_id: id,
                        sequence: 0,
                        status: 0,
                    }),
                    &[],
                    &mut output,
                )
                .await?;
            } else if meta.kind == SessionKind::CloseRequest {
                if let Some(state) = sessions.remove(&id) {
                    send(
                        &mut stream,
                        &mut encoder,
                        Metadata::Session(SessionMetadata {
                            kind: SessionKind::CloseResponse,
                            session_id: id,
                            sequence: state.sequence,
                            status: 0,
                        }),
                        &[],
                        &mut output,
                    )
                    .await?;
                }
                continue;
            }
        }
        let state = sessions.get_mut(&id).unwrap();
        if !state.ready {
            state.request.extend_from_slice(&frame.payload);
            if state.request.len() < 10 {
                continue;
            }
            assert_eq!(state.request[0], 5);
            assert!(matches!(state.request[1], 1 | 3));
            assert_eq!(state.request[2], 0);
            let mut address = &state.request[3..];
            socks5::read_destination(&mut address, true).await?;
            let consumed = state.request.len() - address.len();
            let body = state.request.split_off(consumed);
            state.request.clear();
            state.ready = true;
            data(
                &mut stream,
                &mut encoder,
                id,
                state,
                &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                &mut output,
            )
            .await?;
            data(&mut stream, &mut encoder, id, state, &body, &mut output).await?;
        } else {
            data(
                &mut stream,
                &mut encoder,
                id,
                state,
                &frame.payload,
                &mut output,
            )
            .await?;
        }
    }
    Ok(())
}
pub(super) async fn echo(stream: &mut crate::dispatch::BoxStream, bytes: &[u8]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        stream.write_all(bytes).await.unwrap();
        let mut received = vec![0; bytes.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn mieru_tcp_standard_and_no_wait_client_first_and_udp_business() {
    let probe = ResourceProbe::default();
    probe.scope(async {
        for mode in [MieruHandshake::Standard,MieruHandshake::NoWait] {
            let peer=Peer::new(false);let node=MieruOutbound::new(&config(mode),UpstreamPath::proxy(peer.clone()),1024).unwrap();let context=EstablishContext::with_timeout(Duration::from_secs(5));
            let mut stream=node.connect_stream(session(),&context).await.unwrap().io;
            if mode==MieruHandshake::NoWait {
                let mut byte=[0];let reading=stream.read_exact(&mut byte);tokio::pin!(reading);
                tokio::select!{result=&mut reading=>panic!("read before first write completed: {result:?}"),()=tokio::time::sleep(Duration::from_millis(10))=>{}}
            }
            echo(&mut stream,&vec![1;512]).await;
            let request=DatagramRequest::new(DatagramSession::new(InboundKind::Socks5,"192.0.2.10:1000".parse().unwrap()));
            let mut packet=node.open_datagram(request,&context).await.unwrap();
            let remote=Destination::Ip("198.51.100.1:53".parse().unwrap());let payload=vec![9;4096];packet.send(Datagram{remote:remote.clone(),payload:payload.clone().into(),sniffed_domain:None}).await.unwrap();let response=packet.receive().await.unwrap();assert_eq!(response.remote,remote);assert_eq!(response.payload,payload);
            packet.close().await.unwrap();drop(packet);node.shutdown().await;drop(stream);drop(node);peer.stop().await;
            assert!(peer.ports.lock().unwrap().iter().all(|port|(2000..=2002).contains(port)));
        }
    }).await;
    assert!(probe.snapshot().is_idle());
}
#[tokio::test]
async fn mieru_tcp_stop_joins_partial_physical_frame_and_lazy_reader() {
    let probe = ResourceProbe::default();
    probe.scope(async {
        let peer=Peer::new(true);let node=MieruOutbound::new(&config(MieruHandshake::NoWait),UpstreamPath::proxy(peer.clone()),32).unwrap();let context=EstablishContext::with_timeout(Duration::from_secs(5));
        let mut stream=node.connect_stream(session(),&context).await.unwrap().io;
        let bytes=vec![3;4096];let writing=stream.write_all(&bytes);let mut writing=Box::pin(writing);
        tokio::select!{result=&mut writing=>panic!("write completed on stalled frame: {result:?}"),()=tokio::time::sleep(Duration::from_millis(20))=>{}}
        drop(writing);drop(stream);
        tokio::time::timeout(Duration::from_secs(2),node.shutdown()).await.unwrap();
        assert!(node.client.spawn(Box::pin(async {})).is_err());drop(node);peer.stop().await;
    }).await;
    assert!(probe.snapshot().is_idle());
}
