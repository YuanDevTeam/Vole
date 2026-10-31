//! Node-owned sing-mux adapter over any normal protocol connector.
use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};
use crate::{
    config::SingMuxConfig,
    dispatch::{DatagramTransport, DispatchError},
    session::{Destination, StreamSession},
    transport::sing_mux::{Pool, SuppliedStream, datagram::DatagramIo},
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tokio_util::sync::CancellationToken;

pub struct SingMuxConnector {
    inner: Arc<dyn OutboundConnector>,
    pool: Pool,
    cancellation: CancellationToken,
    tracking: Option<Tracking>,
    #[cfg(target_os = "linux")]
    capture_tcp: bool,
}
struct Tracking {
    registry: Arc<crate::connections::Registry>,
    chain: Arc<str>,
    providers: Vec<Arc<str>>,
}
impl std::fmt::Debug for SingMuxConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingMuxConnector").finish_non_exhaustive()
    }
}
impl SingMuxConnector {
    /// Wrap an inner node with normalized, enabled smux options.
    pub fn new(inner: Arc<dyn OutboundConnector>, options: SingMuxConfig) -> Self {
        Self {
            inner,
            pool: Pool::new(options),
            cancellation: CancellationToken::new(),
            tracking: None,
            #[cfg(target_os = "linux")]
            capture_tcp: false,
        }
    }
    pub(crate) fn with_autonomous_xhttp(mut self, proxy: &crate::config::ProxyConfig) -> Self {
        // Match the proven XUDP path: VLESS Encryption and sing-mux padding
        // retain their own final write, so they cannot inherit this capability.
        let enabled = matches!(
            &proxy.protocol,
            crate::config::ProxyProtocol::Vless(config)
                if config.xhttp().is_some()
                    && matches!(&config.encryption, crate::config::VlessEncryption::None)
        );
        let h2_packet_up = enabled
            && matches!(
                &proxy.protocol,
                crate::config::ProxyProtocol::Vless(config)
                    if config.xhttp().is_some_and(|xhttp| xhttp.mode == crate::config::XHttpMode::PacketUp)
            );
        self.pool.set_autonomous_writes(enabled, h2_packet_up);
        self
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn with_physical_tcp_control(mut self, proxy: &crate::config::ProxyConfig) -> Self {
        self.capture_tcp = self.pool.brutal_enabled() && exclusive_tcp(proxy);
        self
    }
    pub(crate) fn with_tracking(
        mut self,
        diagnostics: &crate::routing::diagnostics::Diagnostics,
        name: &str,
    ) -> Self {
        let chain = diagnostics.text(name);
        self.tracking = Some(Tracking {
            registry: diagnostics.connections.clone(),
            providers: diagnostics.providers(std::slice::from_ref(&chain)),
            chain,
        });
        self
    }
    async fn connect(
        &self,
        mut session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<SuppliedStream> {
        session.destination = Destination::domain("sp.mux.sing-box.arpa", 444)?;
        session.sniffed_domain = None;
        let source = session.source;
        #[cfg(feature = "outbound-vless")]
        let h3_capture = self
            .pool
            .captures_h3_udp()
            .then(crate::transport::xhttp::UdpAssociationCapture::default);
        #[cfg(feature = "outbound-vless")]
        let h3_context = h3_capture
            .as_ref()
            .map(|capture| context.capture_h3_udp(capture.clone()));
        #[cfg(feature = "outbound-vless")]
        let context = h3_context.as_ref().unwrap_or(context);
        #[cfg(target_os = "linux")]
        let capture = self
            .capture_tcp
            .then(crate::dialer::tcp_control::Capture::default);
        #[cfg(target_os = "linux")]
        let captured_context = capture
            .as_ref()
            .map(|capture| context.capture_tcp_control(capture.clone()));
        #[cfg(target_os = "linux")]
        let context = captured_context.as_ref().unwrap_or(context);
        let raw = self
            .inner
            .connect_stream(session, context)
            .await
            .map(|connected| connected.io)
            .map_err(io::Error::other)?;
        let io = match &self.tracking {
            None => raw,
            Some(tracking) => tracking
                .registry
                .open_inner(crate::connections::ConnectionInfo {
                    metadata: crate::connections::ConnectionMetadata {
                        network: "tcp",
                        inbound_type: "Inner",
                        source,
                        destination_ip: None,
                        destination_port: 444,
                        host: Arc::from("sp.mux.sing-box.arpa"),
                        dns_mode: "normal",
                        sniff_host: Arc::from(""),
                        process: Default::default(),
                        original: None,
                    },
                    chains: vec![tracking.chain.clone()],
                    provider_chains: tracking.providers.clone(),
                    rule: "",
                    rule_payload: Arc::from(""),
                    dns_path: Vec::new(),
                })
                .stream(raw),
        };
        Ok(SuppliedStream {
            io,
            #[cfg(target_os = "linux")]
            control: capture.and_then(|capture| capture.finish()),
            #[cfg(feature = "outbound-vless")]
            h3_udp: h3_capture.and_then(|capture| capture.take()),
        })
    }
}
#[cfg(target_os = "linux")]
fn exclusive_tcp(proxy: &crate::config::ProxyConfig) -> bool {
    use crate::config::{
        ProxyProtocol, ShadowsocksPlugin, StreamTransport, TrojanTransport, VlessTransport,
    };
    if proxy.mptcp {
        return false;
    }
    match &proxy.protocol {
        ProxyProtocol::Http(_) | ProxyProtocol::Socks5(_) => true,
        ProxyProtocol::Vless(config) => matches!(
            &config.transport,
            VlessTransport::Stream(StreamTransport::Tcp | StreamTransport::WebSocket { .. })
        ),
        ProxyProtocol::Vmess(config) => matches!(
            &config.transport,
            StreamTransport::Tcp | StreamTransport::WebSocket { .. }
        ),
        ProxyProtocol::Trojan(config) => matches!(
            &config.transport,
            TrojanTransport::Tcp | TrojanTransport::WebSocket { .. }
        ),
        ProxyProtocol::Shadowsocks(config) => !matches!(
            &config.plugin,
            Some(ShadowsocksPlugin::WebSocket { mux: true, .. })
        ),
        _ => false,
    }
}
#[async_trait]
impl OutboundConnector for SingMuxConnector {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let effective_peer = session.destination.clone();
        let io = self
            .pool
            .open(&effective_peer, false, context.deadline(), || {
                self.connect(session, context)
            })
            .await?;
        Ok(ConnectedStream { io, effective_peer })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        tokio::select! { biased;
            ()=self.cancellation.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                if self.pool.only_tcp() { return self.inner.open_datagram(request, context).await; }
                let target = Destination::domain("sp.mux.sing-box.arpa", 444)?;
                let session = StreamSession { metadata:request.session.metadata.clone(), inbound:request.session.inbound, source:request.session.source, destination:target.clone(), sniffed_domain:None };
                let io=self.pool.open(&target, true, context.deadline(), || self.connect(session, context)).await?;
                let transport = DatagramIo::new(io,request.budget(),context.resolution(),context.deadline(),self.cancellation.clone());
                let transport = if self.pool.autonomous_writes() { transport.with_autonomous_writes() } else { transport };
                Ok(crate::dispatch::bound_datagram(Box::new(transport),request.budget()))
            }=>result,
        }
    }
    fn begin_shutdown(&self) {
        self.cancellation.cancel();
        self.pool.begin_stop();
        self.inner.begin_shutdown();
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.pool.stop().await;
        self.inner.shutdown().await;
    }
}
impl Drop for SingMuxConnector {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dispatch::{DatagramBudget, DatagramTransport},
        resources::observation::{ResourceKind, ResourceProbe},
        session::{DatagramSession, InboundKind},
    };
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use tokio::{sync::Notify, time::Instant};

    #[cfg(all(target_os = "linux", feature = "outbound-vless"))]
    #[test]
    fn brutal_physical_control_requires_exclusive_non_mptcp_transport() {
        for (network, extra, allowed) in [
            ("tcp", "", true),
            ("ws", "", true),
            ("grpc", "", false),
            ("xhttp", "", false),
            ("tcp", "mptcp: true", false),
        ] {
            let yaml = format!(
                "mixed-port: 1080\nproxies:\n- name: edge\n  type: vless\n  server: 192.0.2.1\n  port: 443\n  uuid: 07070707-0707-0707-0707-070707070707\n  network: {network}\n  {extra}\nrules: ['MATCH,edge']\n"
            );
            let config = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert_eq!(
                exclusive_tcp(&config.proxies[0]),
                allowed,
                "{network}, {extra}"
            );
        }
    }

    #[cfg(feature = "outbound-vless")]
    #[test]
    fn autonomous_capability_keeps_smux_and_requires_packet_up_for_h2mux() {
        for (network, protocol, mode, padding, encryption, expected) in [
            ("xhttp", "smux", "packet-up", false, false, true),
            ("xhttp", "smux", "stream-one", false, false, true),
            ("xhttp", "smux", "stream-up", false, false, true),
            ("tcp", "smux", "packet-up", false, false, false),
            ("xhttp", "h2mux", "packet-up", false, false, true),
            ("xhttp", "h2mux", "stream-one", false, false, false),
            ("xhttp", "h2mux", "stream-up", false, false, false),
            ("xhttp", "yamux", "packet-up", false, false, false),
            ("xhttp", "smux", "packet-up", true, false, false),
            ("xhttp", "smux", "packet-up", false, true, false),
            ("xhttp", "h2mux", "packet-up", true, false, false),
            ("xhttp", "h2mux", "packet-up", false, true, false),
        ] {
            let yaml = format!(
                "mixed-port: 1080\nproxies:\n- name: edge\n  type: vless\n  server: 192.0.2.1\n  port: 443\n  uuid: 07070707-0707-4707-8707-070707070707\n  network: {network}\n  smux: {{enabled: true, protocol: {protocol}, padding: {padding}}}\nrules: ['MATCH,DIRECT']\n"
            );
            let yaml = if network == "xhttp" {
                yaml.replace(
                    "  smux:",
                    &format!("  xhttp-opts: {{mode: {mode}}}\n  smux:"),
                )
            } else {
                yaml
            };
            let mut config = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
            let proxy = &mut config.proxies[0];
            if encryption {
                let crate::config::ProxyProtocol::Vless(config) = &mut proxy.protocol else {
                    panic!("VLESS test node");
                };
                config.encryption =
                    crate::config::VlessEncryption::MlKem768X25519Plus(String::new());
            }
            let inner = Arc::new(MuxPeer {
                calls: Mutex::default(),
                tasks: Mutex::default(),
                probe: ResourceProbe::default(),
            });
            let node = SingMuxConnector::new(inner, proxy.smux.as_ref().unwrap().clone())
                .with_autonomous_xhttp(proxy);
            assert_eq!(
                node.pool.autonomous_writes(),
                expected,
                "{network}/{protocol}, padding={padding}, encryption={encryption}"
            );
        }
    }

    struct MuxPeer {
        calls: Mutex<Vec<(StreamSession, Instant)>>,
        tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
        probe: ResourceProbe,
    }
    #[async_trait]
    impl OutboundConnector for MuxPeer {
        async fn connect_stream(
            &self,
            session: StreamSession,
            context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            self.calls
                .lock()
                .unwrap()
                .push((session.clone(), context.deadline()));
            let (raw, mut peer) = tokio::io::duplex(65536);
            self.tasks.lock().unwrap().push(tokio::spawn(async move {
                let mut handshake = [0; 2];
                peer.read_exact(&mut handshake).await.unwrap();
                assert_eq!(handshake, [0, 2]);
                let mut connection = h2::server::handshake(peer).await.unwrap();
                let mut streams = Vec::new();
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    assert_eq!(request.method(), "CONNECT");
                    let mut output = reply.send_response(http::Response::new(()), false).unwrap();
                    output
                        .send_data(bytes::Bytes::from_static(b"\x00x"), false)
                        .unwrap();
                    streams.push((request, output));
                }
            }));
            Ok(ConnectedStream {
                io: Box::new(raw),
                effective_peer: session.destination,
            })
        }
        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            panic!("mux UDP must use inner TCP rather than native UDP");
        }
        async fn shutdown(&self) {
            // The wrapper must join its driver before releasing the supplied IO owner.
            assert_eq!(self.probe.snapshot().current(ResourceKind::Task), 0);
            let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
            for task in tasks {
                task.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn shared_wrapper_preserves_logical_peer_and_joins_mux_before_inner() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let inner = Arc::new(MuxPeer {
                    calls: Mutex::default(),
                    tasks: Mutex::default(),
                    probe: probe.clone(),
                });
                let registry = Arc::new(crate::connections::Registry::default());
                let config = crate::config::Config::parse_yaml(b"mixed-port: 1080\nproxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080}]\nrules: ['MATCH,DIRECT']\n").unwrap();
                let rules = crate::routing::RuleSet::compile(config.rules.clone()).unwrap();
                let diagnostics = crate::routing::diagnostics::Diagnostics::new(&config, &rules, registry.clone());
                let node = SingMuxConnector::new(
                    inner.clone(),
                    SingMuxConfig {
                        enabled: true,
                        max_connections: 1,
                        statistic: true,
                        ..Default::default()
                    },
                ).with_tracking(&diagnostics, "edge");
                let session = StreamSession {
                    metadata: crate::session::InboundMetadata {
                        local_port: 1080,
                        user: Some(Arc::from("alice")),
                        ..Default::default()
                    },
                    inbound: InboundKind::Socks5,
                    source: "127.0.0.1:1080".parse().unwrap(),
                    destination: Destination::domain("business.invalid", 443).unwrap(),
                    sniffed_domain: Some("sniffed.invalid".to_owned()),
                };
                let context = EstablishContext::default();
                let mut first = node
                    .connect_stream(session.clone(), &context)
                    .await
                    .unwrap();
                let mut sibling = node
                    .connect_stream(session.clone(), &context)
                    .await
                    .unwrap();
                assert_eq!(first.effective_peer, session.destination);
                assert_eq!(first.io.read_u8().await.unwrap(), b'x');
                assert_eq!(sibling.io.read_u8().await.unwrap(), b'x');
                let calls = inner.calls.lock().unwrap().clone();
                assert_eq!(calls.len(), 1);
                let physical = &calls[0].0;
                assert_eq!(physical.destination.authority(), "sp.mux.sing-box.arpa:444");
                assert_eq!(physical.inbound, session.inbound);
                assert_eq!(physical.source, session.source);
                assert_eq!(physical.metadata, session.metadata);
                assert!(physical.sniffed_domain.is_none());
                assert_eq!(calls[0].1, context.deadline());
                assert_eq!(probe.snapshot().current(ResourceKind::Pool), 1);
                assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
                let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
                assert_eq!(snapshot["connections"].as_array().unwrap().len(), 1);
                assert_eq!(snapshot["connections"][0]["metadata"]["type"], "Inner");
                assert_eq!(snapshot["connections"][0]["chains"], serde_json::json!(["edge"]));
                assert!(snapshot["connections"][0]["upload"].as_u64().unwrap() > 0);
                assert_eq!(snapshot["uploadTotal"], 0);
                assert_eq!(snapshot["downloadTotal"], 0);
                registry.close(snapshot["connections"][0]["id"].as_str().unwrap());
                for stream in [&mut first.io, &mut sibling.io] {
                    assert!(tokio::time::timeout(std::time::Duration::from_secs(1), stream.read_u8()).await.unwrap().is_err());
                }
                node.shutdown().await;
                drop((first, sibling, node));
                assert!(probe.snapshot().is_idle());
            })
            .await;
    }

    #[derive(Default)]
    struct PendingUdp {
        request: Mutex<Option<(DatagramRequest, Instant)>>,
        entered: Notify,
        stopped: Mutex<Vec<&'static str>>,
    }
    #[async_trait]
    impl OutboundConnector for PendingUdp {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            panic!("only-tcp must not establish a mux TCP stream for UDP");
        }
        async fn open_datagram(
            &self,
            request: DatagramRequest,
            context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            *self.request.lock().unwrap() = Some((request, context.deadline()));
            self.entered.notify_one();
            std::future::pending().await
        }
        fn begin_shutdown(&self) {
            self.stopped.lock().unwrap().push("begin");
        }
        async fn shutdown(&self) {
            self.stopped.lock().unwrap().push("joined");
        }
    }

    #[tokio::test]
    async fn only_tcp_delegates_original_udp_metadata_budget_and_cancels_pending_setup() {
        let inner = Arc::new(PendingUdp::default());
        let node = SingMuxConnector::new(
            inner.clone(),
            SingMuxConfig {
                enabled: true,
                only_tcp: true,
                ..Default::default()
            },
        );
        let request = DatagramRequest::new(DatagramSession::new(
            InboundKind::Socks5,
            "127.0.0.1:10234".parse().unwrap(),
        ))
        .with_budget(DatagramBudget::new(913, 1714));
        let context = EstablishContext::default();
        let open = node.open_datagram(request.clone(), &context);
        tokio::pin!(open);
        tokio::select! {
            _ = inner.entered.notified() => {},
            _ = &mut open => panic!("inner setup should remain pending"),
        }
        let recorded = inner.request.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.0.session, request.session);
        assert_eq!(recorded.0.budget(), request.budget());
        assert_eq!(recorded.1, context.deadline());
        node.begin_shutdown();
        assert!(matches!(open.await, Err(DispatchError::NotAllowed)));
        node.shutdown().await;
        assert_eq!(*inner.stopped.lock().unwrap(), ["begin", "begin", "joined"]);
        assert!(matches!(
            node.open_datagram(request, &context).await,
            Err(DispatchError::NotAllowed)
        ));
    }

    #[cfg(feature = "outbound-vless")]
    #[tokio::test]
    async fn private_packet_up_h2mux_hands_off_tail_and_keeps_strong_flush_fin_stop() {
        use crate::session::InboundMetadata;
        use futures_util::task::AtomicWaker;
        use std::{
            pin::Pin,
            sync::atomic::{AtomicBool, Ordering},
            task::{Context, Poll},
            time::Duration,
        };
        use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

        #[derive(Default)]
        struct Gate {
            blocked: AtomicBool,
            wake: AtomicWaker,
        }
        impl Gate {
            fn set(&self, blocked: bool) {
                self.blocked.store(blocked, Ordering::SeqCst);
                self.wake.wake();
            }
        }
        struct GatedIo {
            raw: DuplexStream,
            gate: Arc<Gate>,
        }
        impl AsyncRead for GatedIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.raw).poll_read(cx, out)
            }
        }
        impl AsyncWrite for GatedIo {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.raw).poll_write(cx, bytes)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.gate.wake.register(cx.waker());
                if self.gate.blocked.load(Ordering::SeqCst) {
                    return Poll::Pending;
                }
                Pin::new(&mut self.raw).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.raw).poll_shutdown(cx)
            }
        }
        struct Peer {
            gate: Arc<Gate>,
            tail: Mutex<Option<tokio::sync::oneshot::Sender<Vec<u8>>>>,
            tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
            observed: Arc<Mutex<Vec<u8>>>,
        }
        #[async_trait]
        impl OutboundConnector for Peer {
            async fn connect_stream(
                &self,
                session: StreamSession,
                _: &EstablishContext,
            ) -> Result<ConnectedStream, DispatchError> {
                let (raw, mut peer) = tokio::io::duplex(65536);
                let tail = self.tail.lock().unwrap().take().expect("one physical");
                let observed = self.observed.clone();
                self.tasks.lock().unwrap().push(tokio::spawn(async move {
                    let mut prefix = [0; 2];
                    peer.read_exact(&mut prefix).await.unwrap();
                    assert_eq!(prefix, [0, 2]);
                    let mut connection = h2::server::handshake(peer).await.unwrap();
                    let (request, mut reply) = connection.accept().await.unwrap().unwrap();
                    assert_eq!(request.method(), "CONNECT");
                    let mut output = reply.send_response(http::Response::new(()), false).unwrap();
                    let mut input = request.into_body();
                    let exchange = async move {
                        let mut ready = false;
                        let mut tail = Some(tail);
                        while let Some(data) = input.data().await {
                            let Ok(data) = data else { return; };
                            let count = data.len();
                            let bytes = {
                                let mut bytes = observed.lock().unwrap();
                                bytes.extend_from_slice(&data);
                                bytes.clone()
                            };
                            input.flow_control().release_capacity(count).unwrap();
                            if !ready && bytes.len() >= 9 {
                                assert_eq!(&bytes[..9], &[0, 0, 1, 192, 0, 2, 1, 1, 187]);
                                output.send_data(bytes::Bytes::from_static(b"\x00w"), false).unwrap();
                                ready = true;
                            }
                            if bytes.len() >= 14 && let Some(tail) = tail.take() {
                                tail.send(bytes[9..14].to_vec()).unwrap();
                                output.send_data(bytes::Bytes::from_static(b"echo"), false).unwrap();
                            }
                        }
                        output.send_data(bytes::Bytes::from_static(b"after-fin"), false).unwrap();
                        // Keep the response open so the same pending read must
                        // be woken by node Stop. Connection EOF drops this owner.
                        std::future::pending::<()>().await;
                    };
                    tokio::pin!(exchange);
                    loop {
                        tokio::select! {
                            () = &mut exchange => break,
                            next = connection.accept() => if !matches!(next, Some(Ok(_))) { break; },
                        }
                    }
                }));
                Ok(ConnectedStream {
                    io: Box::new(GatedIo {
                        raw,
                        gate: self.gate.clone(),
                    }),
                    effective_peer: session.destination,
                })
            }
            async fn open_datagram(
                &self,
                _: DatagramRequest,
                _: &EstablishContext,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                panic!("memory peer only supplies authenticated byte IO");
            }
            async fn shutdown(&self) {
                let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
                for task in tasks {
                    task.await.unwrap();
                }
            }
        }
        let gate = Arc::new(Gate::default());
        let (tail, mut tail_rx) = tokio::sync::oneshot::channel();
        let peer = Arc::new(Peer {
            gate: gate.clone(),
            tail: Mutex::new(Some(tail)),
            tasks: Mutex::default(),
            observed: Arc::default(),
        });
        let config = crate::config::Config::parse_yaml(b"mixed-port: 1080\nproxies: [{name: edge, type: vless, server: 192.0.2.1, port: 443, uuid: 07070707-0707-4707-8707-070707070707, network: xhttp, xhttp-opts: {mode: packet-up}, smux: {enabled: true, protocol: h2mux}}]\nrules: ['MATCH,DIRECT']\n").unwrap();
        let proxy = &config.proxies[0];
        let node = SingMuxConnector::new(peer.clone(), proxy.smux.as_ref().unwrap().clone())
            .with_autonomous_xhttp(proxy);
        let session = StreamSession {
            metadata: InboundMetadata::default(),
            inbound: InboundKind::Tun,
            source: "192.0.2.2:12345".parse().unwrap(),
            destination: "192.0.2.1:443"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            sniffed_domain: None,
        };
        let mut stream = node
            .connect_stream(session, &EstablishContext::default())
            .await
            .unwrap();
        assert_eq!(stream.io.read_u8().await.unwrap(), b'w');
        gate.set(true);
        stream.io.write_all(b"tail1").await.unwrap();
        // No following write/flush may rescue the last privately queued chunk.
        let before_flush = tokio::time::timeout(Duration::from_millis(250), &mut tail_rx)
            .await
            .ok()
            .map(Result::unwrap);
        let mut flushing = Box::pin(stream.io.flush());
        let strong_pending = futures_util::poll!(flushing.as_mut()).is_pending();
        gate.set(false);
        tokio::time::timeout(Duration::from_secs(1), flushing)
            .await
            .unwrap()
            .unwrap();
        let actual_tail = match &before_flush {
            Some(bytes) => bytes.clone(),
            None => tokio::time::timeout(Duration::from_secs(1), tail_rx)
                .await
                .unwrap()
                .unwrap(),
        };
        let mut echo = [0; 4];
        stream.io.read_exact(&mut echo).await.unwrap();
        gate.set(true);
        stream.io.write_all(b"close").await.unwrap();
        let mut closing = Box::pin(stream.io.shutdown());
        let fin_pending = futures_util::poll!(closing.as_mut()).is_pending();
        gate.set(false);
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .unwrap()
            .unwrap();
        let mut after_fin = [0; 9];
        stream.io.read_exact(&mut after_fin).await.unwrap();
        let mut reading = Box::pin(stream.io.read_u8());
        let read_pending = futures_util::poll!(reading.as_mut()).is_pending();
        tokio::time::timeout(Duration::from_secs(1), node.shutdown())
            .await
            .unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(1), reading)
            .await
            .unwrap()
            .is_err();
        drop(stream);
        // All physical/core/peer tasks are joined before intended RED assertion.
        assert!(
            strong_pending && fin_pending && read_pending && stopped,
            "strong flush/FIN/Stop fixture failed"
        );
        assert_eq!(actual_tail, b"tail1");
        assert_eq!(&echo, b"echo");
        assert_eq!(&after_fin, b"after-fin");
        assert_eq!(&peer.observed.lock().unwrap()[9..], b"tail1close");
        assert!(
            before_flush.is_some(),
            "private h2mux must hand the final DATA to its driver before a later flush"
        );
    }
}
