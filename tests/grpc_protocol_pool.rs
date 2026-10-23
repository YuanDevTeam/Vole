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

#[derive(Default)]
struct DelayedResponse {
    received: AtomicUsize,
    changed: tokio::sync::Notify,
    cancel: tokio_util::sync::CancellationToken,
}

struct MemoryUpstream {
    physical: AtomicUsize,
    tasks: TaskTracker,
    requests: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    delayed: Option<Arc<DelayedResponse>>,
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
        let delayed = self.delayed.clone();
        let cancel = delayed
            .as_ref()
            .map(|state| state.cancel.clone())
            .unwrap_or_default();
        self.tasks.spawn(async move {
            let mut connection = tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                result = h2::server::handshake(peer) => match result {
                    Ok(connection) => connection,
                    Err(_) => return,
                },
            };
            loop {
                let next = tokio::select! {
                    biased;
                    () = cancel.cancelled() => return,
                    next = connection.accept() => next,
                };
                let Some(Ok((request, mut response))) = next else {
                    break;
                };
                assert_eq!(request.uri().path(), "/edge/Tun");
                assert_eq!(request.headers()["user-agent"], "vmess-memory");
                let send = if delayed.is_some() {
                    None
                } else {
                    Some(
                        response
                            .send_response(
                                http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap(),
                                false,
                            )
                            .unwrap(),
                    )
                };
                let mut receive = request.into_body();
                let requests = requests.clone();
                let delayed = delayed.clone();
                let cancel = cancel.clone();
                sessions.spawn(async move {
                    // Keep SendResponse alive without sending headers. The H2
                    // connection task continues to drive request DATA.
                    let _response = (response, send);
                    let mut first = Vec::new();
                    let mut sent = false;
                    loop {
                        let next = tokio::select! {
                            biased;
                            () = cancel.cancelled() => return,
                            next = receive.data() => next,
                        };
                        let Some(Ok(data)) = next else { break };
                        receive.flow_control().release_capacity(data.len()).unwrap();
                        if let Some(progress) = &delayed {
                            progress.received.fetch_add(data.len(), Ordering::Release);
                            progress.changed.notify_one();
                        }
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
        let upstream=Arc::new(MemoryUpstream { physical:AtomicUsize::new(0), tasks:TaskTracker::new(), requests, delayed:None });
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

#[cfg(feature = "interop-test")]
#[tokio::test(start_paused = true)]
async fn vmess_grpc_committed_request_outlives_delayed_http_response() {
    use tokio::io::AsyncReadExt;
    use vole::resources::observation::ResourceProbe;

    async fn received_after(progress: &DelayedResponse, before: usize) {
        loop {
            let changed = progress.changed.notified();
            if progress.received.load(Ordering::Acquire) > before {
                return;
            }
            changed.await;
        }
    }

    let probe = ResourceProbe::default();
    let (result, core_stopped, naturally_joined, joined) = probe
        .scope(async {
            let config = Config::parse_yaml(
                br#"proxies:
  - name: edge
    type: vmess
    server: fixture.invalid
    port: 443
    uuid: 07070707-0707-0707-0707-070707070707
    network: grpc
    grpc-opts: {grpc-service-name: edge, grpc-user-agent: vmess-memory}
rules: ['MATCH,edge']
"#,
            )
            .unwrap();
            let ProxyProtocol::Vmess(node) = &config.proxies[0].protocol else {
                unreachable!()
            };
            let (requests, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let progress = Arc::new(DelayedResponse::default());
            let upstream = Arc::new(MemoryUpstream {
                physical: AtomicUsize::new(0),
                tasks: TaskTracker::new(),
                requests,
                delayed: Some(progress.clone()),
            });
            let outbound =
                VmessOutbound::new_with_path(node, UpstreamPath::proxy(upstream.clone())).unwrap();
            let session = StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::InternalMeasure,
                source: "127.0.0.1:1".parse().unwrap(),
                destination: "192.0.2.1:80"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
                sniffed_domain: None,
            };
            let context = EstablishContext::with_timeout(Duration::from_secs(2));
            let result = tokio::time::timeout(Duration::from_secs(30), async {
                let stream = outbound
                    .connect_stream(session, &context)
                    .await
                    .map_err(std::io::Error::other)?
                    .io;
                // This event is emitted only after the peer has the complete
                // first Gun record; connect_stream also finished auth flush.
                let _authentication = observed
                    .recv()
                    .await
                    .ok_or(std::io::ErrorKind::UnexpectedEof)?;
                let (mut reader, mut writer) = tokio::io::split(stream);
                let before_upload = progress.received.load(Ordering::Acquire);
                writer.write_all(b"upload before delayed response").await?;
                writer.flush().await?;
                received_after(&progress, before_upload).await;
                let before_late_upload = progress.received.load(Ordering::Acquire);
                let mut byte = [0; 1];
                let before_deadline = tokio::time::Instant::now() < context.deadline();
                let (pending_before, pending_after, boundary_read) = {
                    let read = reader.read(&mut byte);
                    tokio::pin!(read);
                    let initial = futures_util::poll!(read.as_mut());
                    let pending_before = initial.is_pending();
                    let expired = if pending_before {
                        // No real sleep or fixed 10-second assumption. The
                        // response gate stays closed while this clock advances.
                        tokio::time::advance(
                            context
                                .deadline()
                                .saturating_duration_since(tokio::time::Instant::now())
                                + Duration::from_millis(1),
                        )
                        .await;
                        futures_util::poll!(read.as_mut())
                    } else {
                        initial
                    };
                    let pending_after = expired.is_pending();
                    // Keep EOF/Ok(n) distinct from an actual TimedOut error.
                    let boundary_read = format!("{expired:?}");
                    (pending_before, pending_after, boundary_read)
                };
                let continued = if pending_after {
                    writer
                        .write_all(b"upload after original setup deadline")
                        .await?;
                    writer.flush().await?;
                    received_after(&progress, before_late_upload).await;
                    true
                } else {
                    false
                };
                // Clean up even on the expected RED before asserting it. On
                // GREEN, this stops an active stream with no HTTP response.
                outbound.shutdown().await;
                let stopped_read = match reader.read(&mut byte).await {
                    Ok(0) | Err(_) => true,
                    Ok(_) => false,
                };
                let stopped_write = writer.write_all(b"after Stop").await.is_err();
                Ok::<_, std::io::Error>((
                    before_deadline,
                    pending_before,
                    pending_after,
                    boundary_read,
                    continued,
                    stopped_read && stopped_write,
                ))
            })
            .await;
            // Bound a broken Core Stop as well as the scenario itself.
            let core_stopped = tokio::time::timeout(Duration::from_secs(1), outbound.shutdown())
                .await
                .is_ok();
            drop(outbound);
            upstream.tasks.close();
            // First require the Core close to reach the peer naturally. A
            // fallback cancellation must not turn a broken Stop into GREEN.
            let naturally_joined =
                tokio::time::timeout(Duration::from_secs(1), upstream.tasks.wait())
                    .await
                    .is_ok();
            progress.cancel.cancel();
            let joined = tokio::time::timeout(Duration::from_secs(1), upstream.tasks.wait())
                .await
                .is_ok();
            let physical = upstream.physical.load(Ordering::SeqCst);
            (
                result.map(|outcome| outcome.map(|value| (value, physical))),
                core_stopped,
                naturally_joined,
                joined,
            )
        })
        .await;
    assert!(joined, "memory H2 peer tasks must join even after failure");
    assert!(
        probe.snapshot().is_idle(),
        "Core resources must be released"
    );
    assert!(core_stopped, "Core Stop must complete within its watchdog");
    assert!(
        naturally_joined,
        "Core Stop must close the peer without fallback cancellation"
    );
    let (
        (before_deadline, pending_before, pending_after, boundary_read, continued, stopped),
        physical,
    ) = result
        .expect("memory scenario watchdog")
        .expect("memory scenario IO");
    assert!(
        before_deadline,
        "initial read must be polled before the original setup deadline"
    );
    assert!(
        pending_before,
        "peer has not sent HTTP response headers: {boundary_read}"
    );
    assert!(
        pending_after,
        "committed auth must not expire or EOF: {boundary_read}"
    );
    assert!(
        continued,
        "peer must receive upload after original setup deadline"
    );
    assert!(
        stopped,
        "Stop must end pending reads and reject later writes"
    );
    assert_eq!(physical, 1, "no reconnect or replay");
}
