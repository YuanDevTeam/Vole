#![cfg(all(unix, feature = "outbound-vless"))]
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
    outbound::{EstablishContext, OutboundConnector, UpstreamPath, VlessOutbound},
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
async fn vless_all_handshakes_keep_the_original_deadline_and_join_cancelled_io() {
    #[cfg(feature = "interop-test")]
    let _evidence = vole::resources::case_events::Case::new(
        "VLESS-CANCEL",
        "vless_all_handshakes_keep_the_original_deadline_and_join_cancelled_io",
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for mode in ["tcp", "tls", "ws", "grpc", "http", "h2", "vision", "xhttp"] {
        let mut node = serde_json::json!({"name":"edge","type":"vless","server":"fixture.invalid","port":443,"uuid":"07070707-0707-0707-0707-070707070707","network":if mode=="tls" || mode=="vision" {"tcp"}else{mode}});
        match mode {
            "tls" | "xhttp" | "vision" => {
                if mode == "vision" {
                    node["flow"] = serde_json::json!("xtls-rprx-vision");
                }
                node["tls"] = serde_json::json!(true);
            }
            "grpc" => node["grpc-opts"] = serde_json::json!({"grpc-service-name":"edge"}),
            "h2" => node["h2-opts"] = serde_json::json!({"host":["fixture.invalid"]}),
            _ => {}
        }
        let parsed = Config::parse_yaml(
            serde_json::json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let ProxyProtocol::Vless(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        let (io, mut peer) = tokio::io::duplex(65536);
        let outbound = VlessOutbound::new_with_path(
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
        tokio::time::timeout(Duration::from_millis(325), task)
            .await
            .expect("consumer reset the original deadline");
        assert!(start.elapsed() >= Duration::from_millis(240));
        tokio::time::timeout(Duration::from_secs(1), outbound.shutdown())
            .await
            .unwrap();
        let mut observed = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut observed))
            .await
            .unwrap()
            .unwrap();
        assert!(!observed.is_empty());
        assert!(observed.len() <= 65536);
    }
}

struct RejectProtect(AtomicUsize);
impl SocketProtector for RejectProtect {
    fn protect(&self, _: i32) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
fn split_xhttp_construction_uses_default_stack_and_protect_failure_has_no_fallback() {
    // Use the default Rust thread stack. No server or outbound packet:
    // the first socket is rejected by the host-owned protection boundary.
    std::thread::Builder::new().spawn(|| {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            for alpn in ["h3", "h2", "http/1.1"] {
                let raw=serde_json::json!({"mixed-port":1080,"proxies":[{"name":"edge","type":"vless","server":"192.0.2.1","port":443,"uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,"alpn":[alpn],"xhttp-opts":{"mode":"packet-up","reuse-settings":{},"download-settings":{"reuse-settings":{}}}}],"rules":["MATCH,edge"]});
                let parsed=Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
                let ProxyProtocol::Vless(config)=&parsed.proxies[0].protocol else {unreachable!()};
                let protect=Arc::new(RejectProtect(AtomicUsize::new(0)));
                let endpoint=ResolvedEndpoint {logical_host:"192.0.2.1".into(),port:443,addresses:vec!["192.0.2.1:443".parse().unwrap()]};
                let outbound=VlessOutbound::new(config, endpoint, Dialer::default().with_protector(protect.clone())).unwrap();
                let session=StreamSession {metadata: Default::default(),inbound:InboundKind::InternalMeasure,source:"127.0.0.1:1".parse().unwrap(),destination:"192.0.2.2:80".parse::<std::net::SocketAddr>().unwrap().into(),sniffed_domain:None};
                assert!(outbound.connect_stream(session, &EstablishContext::default()).await.is_err());
                assert!((1..=2).contains(&protect.0.load(Ordering::SeqCst)));
                outbound.shutdown().await;
            }
        });
    }).unwrap().join().unwrap();
}

#[tokio::test]
async fn vless_expired_deadline_and_protect_failure_never_fall_back() {
    #[cfg(feature = "interop-test")]
    let _evidence = vole::resources::case_events::Case::new(
        "VLESS-CANCEL",
        "vless_expired_deadline_and_protect_failure_never_fall_back",
    );
    let parsed = Config::parse_yaml(b"mixed-port: 1080\nproxies: [{name: edge, type: vless, server: 192.0.2.1, port: 443, uuid: 07070707-0707-0707-0707-070707070707}]\nrules: ['MATCH,edge']").unwrap();
    let ProxyProtocol::Vless(config) = &parsed.proxies[0].protocol else {
        unreachable!()
    };
    let protect = Arc::new(RejectProtect(AtomicUsize::new(0)));
    let endpoint = ResolvedEndpoint {
        logical_host: "192.0.2.1".into(),
        port: 443,
        addresses: vec!["192.0.2.1:443".parse().unwrap()],
    };
    let outbound = VlessOutbound::new_with_path(
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
