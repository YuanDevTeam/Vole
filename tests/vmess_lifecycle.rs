#![cfg(all(unix, feature = "outbound-vmess"))]
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use vole::{
    config::{Config, ProxyProtocol},
    dialer::{Dialer, ResolvedEndpoint, SocketProtector},
    outbound::{EstablishContext, OutboundConnector, UpstreamPath, vmess::VmessOutbound},
    session::{InboundKind, StreamSession},
};

struct SuppliedStream {
    io: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
}
#[async_trait::async_trait]
impl OutboundConnector for SuppliedStream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _context: &EstablishContext,
    ) -> Result<vole::outbound::ConnectedStream, vole::dispatch::DispatchError> {
        tokio::time::sleep(Duration::from_millis(150)).await;
        Ok(vole::outbound::ConnectedStream {
            io: Box::new(self.io.lock().unwrap().take().unwrap()),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: vole::outbound::DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn vole::dispatch::DatagramTransport>, vole::dispatch::DispatchError> {
        Err(vole::dispatch::DispatchError::NotAllowed)
    }
}

#[tokio::test]
async fn vmess_all_handshakes_keep_the_original_deadline_and_join_cancelled_io() {
    #[cfg(feature = "interop-test")]
    let _evidence = vole::resources::case_events::Case::new(
        "VMESS-CANCEL",
        "vmess_all_handshakes_keep_the_original_deadline_and_join_cancelled_io",
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Plain TCP has already submitted its request before business IO;
    // a delayed VMess response is not an unfinished transport handshake.
    for mode in ["tls", "ws", "grpc", "http", "h2", "upgrade", "upgrade-fast"] {
        let network = if mode == "tls" {
            "tcp"
        } else if mode.starts_with("upgrade") {
            "ws"
        } else {
            mode
        };
        let mut node = serde_json::json!({"name":"edge","type":"vmess","server":"fixture.invalid","port":443,"uuid":"07070707-0707-0707-0707-070707070707","network":network});
        match mode {
            "tls" => {
                node["tls"] = serde_json::json!(true);
            }
            "grpc" => node["grpc-opts"] = serde_json::json!({"grpc-service-name":"edge"}),
            "h2" => node["h2-opts"] = serde_json::json!({"host":["fixture.invalid"]}),
            "upgrade" | "upgrade-fast" => {
                node["ws-opts"] = serde_json::json!({"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":mode=="upgrade-fast"})
            }
            _ => {}
        }
        let parsed = Config::parse_yaml(
            serde_json::json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let ProxyProtocol::Vmess(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        // HTTP's request prefix stays unsubmitted. The other transports still
        // reach their original handshake-response or HTTP/2 SETTINGS wait.
        let capacity = if mode == "http" { 1 } else { 65536 };
        let (io, mut peer) = tokio::io::duplex(capacity);
        let outbound = VmessOutbound::new_with_path(
            node,
            UpstreamPath::proxy(Arc::new(SuppliedStream {
                io: std::sync::Mutex::new(Some(io)),
            })),
        )
        .unwrap();
        let session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::InternalMeasure,
            source: "127.0.0.1:1".parse().unwrap(),
            destination: "192.0.2.2:80"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            sniffed_domain: None,
        };
        let start = tokio::time::Instant::now();
        let context = EstablishContext::with_timeout(Duration::from_millis(250));
        let task = async {
            if let Ok(mut connected) = outbound.connect_stream(session, &context).await {
                let _ = connected.io.write_all(b"first").await;
                let _ = connected.io.flush().await;
                assert!(connected.io.read(&mut [0; 1]).await.is_err());
            }
        };
        let result = tokio::time::timeout(Duration::from_millis(325), task).await;
        let elapsed = start.elapsed();
        let stopped = tokio::time::timeout(Duration::from_secs(1), outbound.shutdown()).await;
        let mut observed = Vec::new();
        let joined =
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut observed)).await;
        stopped.expect("Core Stop did not join");
        joined.expect("memory peer did not finish").unwrap();
        result.expect("consumer reset the original deadline");
        assert!(elapsed >= Duration::from_millis(240));
        assert!(!observed.is_empty());
        assert!(observed.len() <= capacity);
    }
}

struct RejectProtect(AtomicUsize);
impl SocketProtector for RejectProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

#[tokio::test]
async fn vmess_expired_deadline_and_protect_failure_never_fall_back() {
    #[cfg(feature = "interop-test")]
    let _evidence = vole::resources::case_events::Case::new(
        "VMESS-CANCEL",
        "vmess_expired_deadline_and_protect_failure_never_fall_back",
    );
    let parsed = Config::parse_yaml(b"mixed-port: 1080\nproxies: [{name: edge, type: vmess, server: 192.0.2.1, port: 443, uuid: 07070707-0707-0707-0707-070707070707}]\nrules: ['MATCH,edge']").unwrap();
    let ProxyProtocol::Vmess(config) = &parsed.proxies[0].protocol else {
        unreachable!()
    };
    let protect = Arc::new(RejectProtect(AtomicUsize::new(0)));
    let endpoint = ResolvedEndpoint {
        logical_host: "192.0.2.1".into(),
        port: 443,
        addresses: vec!["192.0.2.1:443".parse().unwrap()],
    };
    let outbound = VmessOutbound::new_with_path(
        config,
        UpstreamPath::direct(endpoint, Dialer::default().with_protector(protect.clone())),
    )
    .unwrap();
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: "192.0.2.2:80"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        sniffed_domain: None,
    };
    assert!(
        outbound
            .connect_stream(
                session.clone(),
                &EstablishContext::with_timeout(Duration::ZERO)
            )
            .await
            .is_err()
    );
    assert_eq!(protect.0.load(Ordering::SeqCst), 0);
    assert!(
        outbound
            .connect_stream(session.clone(), &EstablishContext::default())
            .await
            .is_err()
    );
    assert_eq!(protect.0.load(Ordering::SeqCst), 1);
    outbound.shutdown().await;
    assert!(
        outbound
            .connect_stream(session, &EstablishContext::default())
            .await
            .is_err()
    );
    assert_eq!(protect.0.load(Ordering::SeqCst), 1);
}

// This tests the actual outbound call site and complete-request submission,
// rather than retaining a post-establishment response-header timeout.
#[tokio::test(start_paused = true)]
async fn vmess_unsubmitted_request_keeps_original_deadline_and_releases_partial_io() {
    use tokio::io::AsyncReadExt;

    let parsed = Config::parse_yaml(br#"proxies:
  - {name: edge, type: vmess, server: fixture.invalid, port: 443, uuid: 07070707-0707-0707-0707-070707070707}
rules: ['MATCH,edge']
"#).unwrap();
    let ProxyProtocol::Vmess(node) = &parsed.proxies[0].protocol else {
        unreachable!()
    };
    // A complete authenticated VMess request cannot fit this unread pipe.
    let (io, mut peer) = tokio::io::duplex(1);
    let outbound = VmessOutbound::new_with_path(
        node,
        UpstreamPath::proxy(Arc::new(SuppliedStream {
            io: std::sync::Mutex::new(Some(io)),
        })),
    )
    .unwrap();
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: "192.0.2.2:80"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        sniffed_domain: None,
    };
    let context = EstablishContext::with_timeout(Duration::from_millis(250));
    {
        let connect = outbound.connect_stream(session, &context);
        tokio::pin!(connect);
        assert!(futures_util::poll!(connect.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(151)).await;
        assert!(futures_util::poll!(connect.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(
            connect.await.is_err(),
            "request-prefix timeout cannot be released before successful submission"
        );
    }
    outbound.shutdown().await;
    let mut prefix = Vec::new();
    peer.read_to_end(&mut prefix).await.unwrap();
    assert_eq!(prefix.len(), 1);
}
