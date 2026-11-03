//! Actual VLESS -> XHTTP/H3 -> inner h2mux over bounded in-memory datagrams.
//! Raw native probes run only while the H3 acceptor is parked, never as HTTP data.
use super::*;
use crate::outbound::{
    ConnectedStream, DatagramRequest, EstablishContext, SingMuxConnector, UpstreamPath,
};
use crate::session::{DatagramSession, InboundKind, StreamSession};
use std::sync::atomic::AtomicU8;
use tokio::io::AsyncReadExt;
use tokio_util::task::TaskTracker;

#[derive(Default)]
struct NoNetwork {
    calls: AtomicUsize,
}
#[async_trait]
impl OutboundConnector for NoNetwork {
    async fn connect_stream(
        &self,
        _: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        assert!(
            context.h3_udp_capture().is_none(),
            "capture crossed a TCP proxy hop"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        assert!(
            context.h3_udp_capture().is_none(),
            "capture crossed a datagram proxy hop"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(DispatchError::NotAllowed)
    }
}
fn configured() -> (SingMuxConnector, XHttpClient, Arc<NoNetwork>) {
    let config = crate::config::Config::parse_yaml(
        br#"proxies:
- name: fixture
  type: vless
  server: 192.0.2.2
  port: 443
  uuid: 00000000-0000-0000-0000-000000000001
  tls: true
  servername: localhost
  network: xhttp
  alpn: [h3]
  smux: {enabled: true, protocol: h2mux, max-connections: 1, only-tcp: false}
  xhttp-opts:
    path: /x
    mode: packet-up
    reuse-settings: {h-max-request-times: '4'}
rules: ['MATCH,DIRECT']
"#,
    )
    .unwrap();
    let proxy = &config.proxies[0];
    let crate::config::ProxyProtocol::Vless(settings) = &proxy.protocol else {
        panic!("not VLESS")
    };
    let upstream = Arc::new(NoNetwork::default());
    let mut vless = VlessOutbound::new_with_upstream(settings, upstream.clone()).unwrap();
    vless.configure_shared_xhttp_transport(proxy.smux.as_ref());
    let client = vless.test_xhttp_clients().unwrap().0;
    let mux = SingMuxConnector::new(Arc::new(vless), proxy.smux.clone().unwrap())
        .with_autonomous_xhttp(proxy);
    (mux, client, upstream)
}
fn tcp_session() -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::Tun,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: Destination::Ip("192.0.2.9:443".parse().unwrap()),
        sniffed_domain: None,
    }
}
fn udp_request() -> DatagramRequest {
    DatagramRequest::new(DatagramSession::new(
        InboundKind::Tun,
        "192.0.2.10:40001".parse().unwrap(),
    ))
}
#[derive(Default)]
struct Behavior {
    next_post: AtomicU8, //0=normal,1=reject,2=hold the genuine POST response.
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
struct Bridge {
    park: mpsc::Sender<oneshot::Sender<Peer>>,
    resume: mpsc::Sender<Peer>,
    behavior: Arc<Behavior>,
}
impl Bridge {
    async fn park(&self) -> Peer {
        let (send, receive) = oneshot::channel();
        assert!(self.park.send(send).await.is_ok());
        receive.await.unwrap()
    }
    async fn resume(&self, peer: Peer) {
        assert!(self.resume.send(peer).await.is_ok());
    }
}
fn tracked(
    tasks: &TaskTracker,
    cancel: &CancellationToken,
    future: impl Future<Output = ()> + Send + 'static,
) {
    let cancel = cancel.clone();
    tasks.spawn(async move {
        tokio::select! { biased; ()=cancel.cancelled()=>{}, ()=future=>{} }
    });
}
fn bridge(fixture: &mut Fixture, mut peer: Peer) -> Bridge {
    let (client, mut server) = tokio::io::duplex(256 * 1024);
    let (up, down) = tokio::io::split(client);
    let write = Arc::new(tokio::sync::Mutex::new((0_u64, down)));
    let advanced = Arc::new(tokio::sync::Notify::new());
    let (park, mut parks) = mpsc::channel::<oneshot::Sender<Peer>>(1);
    let (resume, mut resumes) = mpsc::channel(1);
    let behavior = Arc::new(Behavior::default());
    let behavior_task = behavior.clone();
    let cancel = fixture.cancel.clone();
    fixture.tasks.push(tokio::spawn(async move {
        let children = TaskTracker::new();
        let mut read = Some(up);
        loop {
            tokio::select! { biased;
                ()=cancel.cancelled()=>break,
                Some(reply)=parks.recv()=>{
                    assert!(reply.send(peer).is_ok());
                    let returned=tokio::select! { biased; ()=cancel.cancelled()=>None, returned=resumes.recv()=>returned }; let Some(returned)=returned else { break; };
                    peer=returned;
                },
                accepted=peer.accept()=>{
                    let Ok(Some(resolver))=accepted else { break; };
                    let Ok((request,mut stream))=resolver.resolve_request().await else { break; };
                    if request.method()==http::Method::GET {
                        let mut read=read.take().expect("one genuine XHTTP carrier GET");
                        tracked(&children,&cancel,async move {
                            if stream.send_response(http::Response::new(())).await.is_err(){return;}
                            let mut bytes=[0;16*1024];
                            loop {
                                let Ok(count)=read.read(&mut bytes).await else {return;};
                                if count==0 {let _=stream.finish().await;return;}
                                if stream.send_data(Bytes::copy_from_slice(&bytes[..count])).await.is_err(){return;}
                            }
                        });
                    } else {
                        assert_eq!(request.method(),http::Method::POST);
                        let sequence=request.uri().path().rsplit('/').next().unwrap().parse::<u64>().unwrap();
                        let write=write.clone(); let advanced=advanced.clone(); let behavior=behavior_task.clone();
                        tracked(&children,&cancel,async move {
                            // Request task scheduling is not a POST sequence oracle.
                            // Fixed next_seq + the existing stream suffice: no map or
                            // second payload buffer, and responses can still overlap.
                            let mut ordered=loop {
                                let changed=advanced.notified();tokio::pin!(changed);changed.as_mut().enable();
                                let ordered=write.lock().await;
                                assert!(sequence>=ordered.0,"duplicate POST sequence");
                                if sequence==ordered.0 {break ordered;}
                                drop(ordered);changed.await;
                            };
                            loop {
                                let mut data=match stream.recv_data().await {
                                    Ok(Some(data))=>data, Ok(None)=>break, Err(_)=>return,
                                };
                                while data.has_remaining() {
                                    let bytes=data.copy_to_bytes(data.remaining());
                                    if ordered.1.write_all(&bytes).await.is_err(){return;}
                                }
                            }
                            if ordered.1.flush().await.is_err(){return;}
                            ordered.0=ordered.0.checked_add(1).unwrap();
                            drop(ordered);advanced.notify_waiters();
                            let mode=behavior.next_post.swap(0,Ordering::SeqCst);
                            if mode!=0 {behavior.entered.notify_one();}
                            if mode==2 {behavior.release.notified().await;}
                            let status=if mode==1 {500}else{200};
                            if stream.send_response(http::Response::builder().status(status).body(()).unwrap()).await.is_ok(){let _=stream.finish().await;}
                        });
                    }
                }
            }
        }
        children.close();children.wait().await;
    }));
    // Real VLESS authentication bytes and mux protocol preface, then real h2.
    let cancel = fixture.cancel.clone();
    fixture.tasks.push(tokio::spawn(async move {
        let children = TaskTracker::new();
        let operation = async {
            let destination = Destination::domain("sp.mux.sing-box.arpa", 444).unwrap();
            let expected = crate::outbound::encode_request_header(
                uuid::Uuid::from_u128(1),
                crate::outbound::VlessCommand::Tcp,
                Some(&destination),
            )
            .unwrap();
            let mut header = vec![0; expected.len()];
            server.read_exact(&mut header).await.unwrap();
            assert_eq!(header.as_slice(), expected.as_ref());
            server.write_all(&[0, 0]).await.unwrap();
            server.flush().await.unwrap();
            let mut protocol = [0; 2];
            server.read_exact(&mut protocol).await.unwrap();
            assert_eq!(protocol, [0, 2]);
            let mut connection = h2::server::handshake(server).await.unwrap();
            while let Some(Ok((request, mut response))) = connection.accept().await {
                tracked(&children, &cancel, async move {
                    let mut input = request.into_body();
                    let Some(Ok(first)) = input.data().await else {
                        return;
                    };
                    let mut metadata = first.to_vec();
                    input.flow_control().release_capacity(first.len()).unwrap();
                    assert!(metadata.len() >= 2);
                    let udp = metadata[..2] == [0, 3];
                    assert!(udp || metadata[..2] == [0, 0]);
                    let target = if udp {
                        Destination::domain("sp.mux.sing-box.arpa", 444).unwrap()
                    } else {
                        tcp_session().destination
                    };
                    let mut expected = vec![0, if udp { 3 } else { 0 }];
                    crate::socks5::encode_address(&target, &mut expected).unwrap();
                    while metadata.len() < expected.len() {
                        let Some(Ok(bytes)) = input.data().await else {
                            return;
                        };
                        metadata.extend_from_slice(&bytes);
                        input.flow_control().release_capacity(bytes.len()).unwrap();
                    }
                    assert_eq!(metadata, expected);
                    let Ok(mut output) = response.send_response(http::Response::new(()), false)
                    else {
                        return;
                    };
                    output.send_data(Bytes::from_static(&[0]), false).unwrap();
                    while let Some(Ok(bytes)) = input.data().await {
                        input.flow_control().release_capacity(bytes.len()).unwrap();
                        if output.send_data(bytes, false).is_err() {
                            return;
                        }
                    }
                    let _ = output.send_data(Bytes::new(), true);
                });
            }
        };
        tokio::select! {biased;()=cancel.cancelled()=>{},()=operation=>{}}
        children.close();
        children.wait().await;
    }));
    Bridge {
        park,
        resume,
        behavior,
    }
}
fn native(fixture: &Fixture) -> quinn::Connection {
    let SendRequest::H3(sender) = fixture.sender.as_ref().unwrap() else {
        panic!("not H3")
    };
    sender.observation.clone()
}
async fn native_prefix(fixture: &Fixture, native: &quinn::Connection, raised: bool) {
    let server = fixture.native_peer.as_ref().unwrap();
    let mut warm = native.open_bi().await.unwrap().0;
    warm.write_all(b"warm").await.unwrap();
    warm.finish().unwrap();
    let (_, mut receive) = server.accept_bi().await.unwrap();
    assert_eq!(receive.read_to_end(4).await.unwrap(), b"warm");
    assert_eq!(warm.stopped().await.unwrap(), None);
    fixture.gate.set(true);
    let (mut send, _) = native.open_bi().await.unwrap();
    let bytes = vec![0xa5; 256 * 1024];
    let prefix = send.write(&bytes).await.unwrap();
    if raised {
        assert!(
            prefix > 160 * 1024 && prefix <= 192 * 1024,
            "raised prefix={prefix}"
        );
    } else {
        assert!(prefix > 0 && prefix <= 64 * 1024, "initial prefix={prefix}");
    }
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut send).poll_write(cx, b"blocked")))
            .await
            .is_pending()
    );
    fixture.gate.set(false);
    let (finished, delivered) = tokio::join!(
        async {
            send.write_all(&bytes[prefix..]).await.unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap()
        },
        async {
            let (_, mut receive) = server.accept_bi().await.unwrap();
            receive.read_to_end(bytes.len()).await.unwrap()
        }
    );
    assert_eq!(finished, None);
    assert_eq!(delivered, bytes);
}
#[tokio::test]
async fn udp_metadata_flush_raises_only_its_live_carrier_after_outer_retirement() {
    let (mux, client, upstream) = configured();
    let mut a = Fixture::new(client.clone(), false, 32, 256 * 1024);
    let mut b = Fixture::new(client.clone(), false, 32, 256 * 1024);
    let result = AssertUnwindSafe(timeout(LIMIT, async {
        let peer = a.initialize().await;
        let service = bridge(&mut a, peer);
        let native_a = native(&a);
        let SendRequest::H3(sender) = a.sender.as_ref().unwrap() else {
            panic!("not H3")
        };
        let weak = Arc::downgrade(sender.udp_control.as_ref().unwrap());
        let mut tcp = mux
            .connect_stream(tcp_session(), &EstablishContext::default())
            .await
            .unwrap()
            .io;
        tcp.write_all(b"tcp").await.unwrap();
        tcp.flush().await.unwrap();
        let mut echoed = [0; 3];
        tcp.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"tcp");
        let parked = service.park().await;
        native_prefix(&a, &native_a, false).await;
        service.resume(parked).await;
        let mut leases = Vec::new();
        for _ in 0..2 {
            let (_, lease) = client
                .acquire(false, || async { Err(io::Error::other("must reuse A")) })
                .await
                .unwrap();
            leases.push(lease);
        }
        // Four acquisitions exhaust A's real request-retirement budget. B's
        // actual acquire removes A from candidates while A's carrier is alive.
        let _peer_b = b.initialize().await;
        let native_b = native(&b);
        assert_ne!(native_a.stable_id(), native_b.stable_id());
        a.sender.take();
        assert!(
            weak.upgrade().is_some(),
            "live PacketUp writer lost its physical control after outer retirement"
        );
        let mut udp = mux
            .open_datagram(udp_request(), &EstablishContext::default())
            .await
            .unwrap();
        let packet = Datagram {
            remote: Destination::Ip("192.0.2.9:53".parse().unwrap()),
            payload: Bytes::from_static(b"udp"),
            sniffed_domain: None,
        };
        udp.send(packet.clone()).await.unwrap();
        let echoed = udp.receive().await.unwrap();
        assert_eq!(echoed.remote, packet.remote);
        assert_eq!(echoed.payload, packet.payload);
        let parked = service.park().await;
        native_prefix(&a, &native_a, true).await;
        native_prefix(&b, &native_b, false).await;
        // A clone losing eligibility cannot inherit B's raise-capable pool.
        let mut ordinary = client.clone();
        ordinary.set_shared_packet_up_transport(false);
        let called = AtomicUsize::new(0);
        assert!(
            ordinary
                .acquire(false, || async {
                    called.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::other("new ordinary pool"))
                })
                .await
                .is_err()
        );
        assert_eq!(called.load(Ordering::SeqCst), 1);
        let mut blocked = native_a.open_bi().await.unwrap().0;
        a.gate.set(true);
        assert!(blocked.write(&vec![1; 256 * 1024]).await.unwrap() > 0);
        let mut pending = Box::pin(blocked.write_all(&[1; 16]));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(pending);
        mux.shutdown().await;
        assert!(blocked.write(b"late").await.is_err());
        drop(parked);
        drop(leases);
        drop(udp);
        drop(tcp);
        drop(native_a);
        drop(native_b);
        a.stop().await;
        b.stop().await;
        assert!(
            weak.upgrade().is_none(),
            "Weak extended the stopped physical owner"
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }))
    .catch_unwind()
    .await;
    mux.shutdown().await;
    a.stop().await;
    b.stop().await;
    finish(result);
}
#[tokio::test]
async fn failed_or_cancelled_udp_metadata_does_not_invoke_the_physical_raise() {
    for mode in [1, 2] {
        let (mux, client, _) = configured();
        let mut fixture = Fixture::new(client, false, 32, 256 * 1024);
        let result=AssertUnwindSafe(timeout(LIMIT,async {
            let peer=fixture.initialize().await;let service=bridge(&mut fixture,peer);
            let SendRequest::H3(sender)=fixture.sender.as_ref().unwrap() else {panic!("not H3")};
            let control=sender.udp_control.as_ref().unwrap().clone();assert!(!control.was_raised());
            let mut tcp=mux.connect_stream(tcp_session(),&EstablishContext::default()).await.unwrap().io;
            tcp.write_all(b"tcp").await.unwrap();tcp.flush().await.unwrap();let mut echo=[0;3];tcp.read_exact(&mut echo).await.unwrap();
            service.behavior.next_post.store(mode,Ordering::SeqCst);
            let context=EstablishContext::default();let mut opening=Box::pin(mux.open_datagram(udp_request(),&context));
            if mode==1 {assert!(opening.await.is_err());}
            else {
                tokio::select!{biased;result=&mut opening=>panic!("held metadata flush completed: {}",result.is_ok()),()=service.behavior.entered.notified()=>{}}
                assert!(std::future::poll_fn(|cx|Poll::Ready(opening.as_mut().poll(cx))).await.is_pending());drop(opening);
            }
            // This is the real selected physical's production once flag. Native
            // credit itself is observed before/after the genuine successful
            // association in the sibling test; do not consume cancellation's
            // still-queued legitimate H3 POST as an unrelated raw probe.
            assert!(!control.was_raised());drop(control);drop(tcp);mux.shutdown().await;
        })).catch_unwind().await;
        mux.shutdown().await;
        fixture.stop().await;
        finish(result);
    }
}
#[tokio::test]
async fn proxy_hops_clear_the_carrier_h3_capture_for_tcp_and_datagrams() {
    let upstream = Arc::new(NoNetwork::default());
    let path = UpstreamPath::proxy(upstream.clone());
    let capture = UdpAssociationCapture::default();
    let context = EstablishContext::default().capture_h3_udp(capture.clone());
    assert!(
        path.connect_server(
            tcp_session(),
            &Destination::Ip("192.0.2.2:443".parse().unwrap()),
            &context
        )
        .await
        .is_err()
    );
    assert!(path.open_datagram(udp_request(), &context).await.is_err());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    assert!(context.h3_udp_capture().is_some());
    assert!(capture.take().is_none());
}
