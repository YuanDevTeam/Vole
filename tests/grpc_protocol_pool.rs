#![cfg(feature = "outbound-vmess")]
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio_util::task::TaskTracker;
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        vmess::VmessOutbound,
    },
    session::{InboundKind, StreamSession},
};

struct MemoryUpstream {
    physical: AtomicUsize,
    tasks: TaskTracker,
    requests: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}
#[async_trait::async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.physical.fetch_add(1, Ordering::SeqCst);
        let (io, peer) = tokio::io::duplex(65536);
        let sessions = self.tasks.clone();
        let requests = self.requests.clone();
        self.tasks.spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            while let Some(Ok((request, mut response))) = connection.accept().await {
                assert_eq!(request.uri().path(), "/edge/Tun");
                assert_eq!(request.headers()["user-agent"], "vmess-memory");
                let send = response
                    .send_response(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                let mut receive = request.into_body();
                let requests = requests.clone();
                sessions.spawn(async move {
                    let _response = send;
                    let mut first = Vec::new();
                    let mut sent = false;
                    while let Some(Ok(data)) = receive.data().await {
                        receive.flow_control().release_capacity(data.len()).unwrap();
                        if !sent {
                            first.extend_from_slice(&data);
                            if first.len() >= 5 {
                                let length =
                                    u32::from_be_bytes(first[1..5].try_into().unwrap()) as usize;
                                assert!(length <= 16384);
                                if first.len() >= 5 + length {
                                    requests.send(first.clone()).unwrap();
                                    sent = true;
                                }
                            }
                        }
                    }
                });
            }
        });
        Ok(ConnectedStream {
            io: Box::new(io),
            effective_peer: session.destination,
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

fn auth_id(record: &[u8]) -> &[u8] {
    assert_eq!(record[0], 0);
    assert_eq!(record[5], 0x0a);
    let mut start = 6;
    while record[start] & 0x80 != 0 {
        start += 1;
    }
    &record[start + 1..start + 17]
}

#[tokio::test]
async fn vmess_grpc_reuses_per_node_transport_with_fresh_authentication_and_joined_stop() {
    tokio::time::timeout(Duration::from_secs(3),async {
        let config=Config::parse_yaml(b"mixed-port: 1080\nproxies: [{name: edge, type: vmess, server: fixture.invalid, port: 443, uuid: 07070707-0707-0707-0707-070707070707, network: grpc, grpc-opts: {grpc-service-name: edge, grpc-user-agent: vmess-memory}}]\nrules: ['MATCH,edge']").unwrap();
        let ProxyProtocol::Vmess(node)=&config.proxies[0].protocol else { unreachable!() };
        let (requests,mut observed)=tokio::sync::mpsc::unbounded_channel();
        let upstream=Arc::new(MemoryUpstream { physical:AtomicUsize::new(0), tasks:TaskTracker::new(), requests });
        let first=VmessOutbound::new_with_path(node,UpstreamPath::proxy(upstream.clone())).unwrap();
        let second=VmessOutbound::new_with_path(node,UpstreamPath::proxy(upstream.clone())).unwrap();
        let session=StreamSession { metadata:Default::default(), inbound:InboundKind::InternalMeasure, source:"127.0.0.1:1".parse().unwrap(), destination:"192.0.2.1:80".parse::<std::net::SocketAddr>().unwrap().into(), sniffed_domain:None };
        let context=EstablishContext::with_timeout(Duration::from_secs(2));
        let mut stream1=first.connect_stream(session.clone(),&context).await.unwrap().io;
        let header1=observed.recv().await.unwrap();
        let mut stream2=first.connect_stream(session.clone(),&context).await.unwrap().io;
        let header2=observed.recv().await.unwrap();
        assert_eq!(upstream.physical.load(Ordering::SeqCst),1,"logical reuse must not reselect or dial the upstream");
        assert_ne!(auth_id(&header1),auth_id(&header2),"each logical stream needs fresh VMess AEAD authentication");
        stream1.shutdown().await.unwrap();
        stream2.write_all(b"sibling").await.unwrap();
        stream2.flush().await.unwrap();
        let mut independent=second.connect_stream(session,&context).await.unwrap().io;
        let _=observed.recv().await.unwrap();
        assert_eq!(upstream.physical.load(Ordering::SeqCst),2,"distinct node instances must not share a physical pool");
        first.shutdown().await;
        assert!(stream2.write_all(b"stopped").await.is_err());
        independent.write_all(b"other-node").await.unwrap();
        independent.flush().await.unwrap();
        second.shutdown().await;
        drop((stream1,stream2,independent));
        upstream.tasks.close();
        upstream.tasks.wait().await;
    }).await.unwrap();
}
