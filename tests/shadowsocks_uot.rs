#![cfg(feature = "outbound-shadowsocks")]
//! Public connector behavior over bounded memory IO; no host protocol server.
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use shadowsocks::{
    config::ServerType, context::Context, relay::tcprelay::proxy_stream::ProxyServerStream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, ShadowsocksOutbound,
        UpstreamPath,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

struct MemoryUpstream(Mutex<Option<BoxStream>>);
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: self.0.lock().unwrap().take().unwrap(),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("UoT must not request native UDP from its upstream")
    }
}

fn request() -> DatagramRequest {
    DatagramRequest::new(DatagramSession::new(
        InboundKind::Socks5,
        "127.0.0.1:1234".parse().unwrap(),
    ))
}

fn packet(size: usize) -> Datagram {
    Datagram {
        remote: Destination::Ip("127.0.0.1:53".parse().unwrap()),
        payload: Bytes::from(vec![7; size]),
        sniffed_domain: None,
    }
}

fn fixture(cipher: &str, capacity: usize) -> (ShadowsocksOutbound, tokio::io::DuplexStream) {
    let key = vec![7; if cipher.contains("aes-128") { 16 } else { 32 }];
    let yaml = serde_json::json!({
        "mixed-port":1080,"proxies":[{"name":"ss","type":"ss","server":"fixture.invalid",
        "port":443,"cipher":cipher,"password":STANDARD.encode(key),"udp":true,
        "udp-over-tcp":true,"udp-over-tcp-version":2}],"rules":["MATCH,ss"]
    });
    let config = Config::parse_yaml(&serde_json::to_vec(&yaml).unwrap()).unwrap();
    let ProxyProtocol::Shadowsocks(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let (raw, peer) = tokio::io::duplex(capacity);
    let outbound = ShadowsocksOutbound::new_with_path(
        config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(raw)))))),
    )
    .unwrap();
    (outbound, peer)
}

fn decoder(
    peer: tokio::io::DuplexStream,
    cipher: &str,
) -> ProxyServerStream<tokio::io::DuplexStream> {
    ProxyServerStream::from_stream(
        Context::new_shared(ServerType::Server),
        peer,
        cipher.parse().unwrap(),
        &vec![7; if cipher.contains("aes-128") { 16 } else { 32 }],
    )
}

const CIPHERS: [&str; 3] = [
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

#[tokio::test]
async fn never_sent_close_drop_and_stop_release_io_without_an_empty_ss_write() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("UOT-SS", "never_sent");
    for cipher in CIPHERS {
        for ending in ["close", "drop", "stop"] {
            let (outbound, mut peer) = fixture(cipher, 64);
            let mut association = Some(
                outbound
                    .open_datagram(request(), &EstablishContext::default())
                    .await
                    .unwrap(),
            );
            match ending {
                "close" => association.as_mut().unwrap().close().await.unwrap(),
                "drop" => drop(association.take()),
                _ => outbound.shutdown().await,
            }
            let mut wire = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut wire))
                .await
                .unwrap()
                .unwrap();
            assert!(
                wire.is_empty(),
                "{cipher} {ending} emitted SS initialization"
            );
            outbound.shutdown().await;
            assert!(
                outbound
                    .open_datagram(request(), &EstablishContext::default())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn late_first_packet_uses_original_deadline_but_established_io_does_not() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("UOT-SS", "deadline");
    let (outbound, mut peer) = fixture(CIPHERS[0], 4096);
    let context = EstablishContext::with_timeout(Duration::from_secs(2));
    let mut association = outbound.open_datagram(request(), &context).await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(association.send(packet(0)).await.is_err());
    outbound.shutdown().await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);

    let (outbound, peer) = fixture(CIPHERS[0], 4096);
    let mut association = outbound
        .open_datagram(
            request(),
            &EstablishContext::with_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    association.send(packet(0)).await.unwrap();
    let mut decoded = decoder(peer, CIPHERS[0]);
    assert_eq!(
        decoded.handshake().await.unwrap(),
        ("sp.v2.udp-over-tcp.arpa".to_owned(), 0).into()
    );
    let mut first = [0; 17];
    decoded.read_exact(&mut first).await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    association.send(packet(0)).await.unwrap();
    let mut next = [0; 9];
    decoded.read_exact(&mut next).await.unwrap();
    assert_eq!(&first[8..], &next);
    outbound.shutdown().await;
    assert_eq!(decoded.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn cancelled_partial_send_resumes_and_stop_releases_a_blocked_writer() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("UOT-SS", "cancel_write");
    for stop in [false, true] {
        let (outbound, peer) = fixture(CIPHERS[0], 64);
        let mut association = outbound
            .open_datagram(request(), &EstablishContext::default())
            .await
            .unwrap();
        assert!(association.supports_shared_destinations());
        if stop {
            let (sent, ()) = tokio::join!(association.send(packet(65_535)), async {
                tokio::task::yield_now().await;
                outbound.shutdown().await;
            });
            assert!(sent.is_err());
            let mut peer = peer;
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert!(bytes.len() <= 64);
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(10), association.send(packet(65_535)))
                    .await
                    .is_err()
            );
            let decoding = tokio::spawn(async move {
                let mut decoded = decoder(peer, CIPHERS[0]);
                assert_eq!(
                    decoded.handshake().await.unwrap(),
                    ("sp.v2.udp-over-tcp.arpa".to_owned(), 0).into()
                );
                let mut header = [0; 17];
                decoded.read_exact(&mut header).await.unwrap();
                assert_eq!(
                    header,
                    [0, 1, 127, 0, 0, 1, 0, 53, 0, 127, 0, 0, 1, 0, 53, 255, 255]
                );
                let mut payload = vec![0; 65_535];
                decoded.read_exact(&mut payload).await.unwrap();
                assert!(payload.iter().all(|byte| *byte == 7));
                let mut next = [0; 9];
                decoded.read_exact(&mut next).await.unwrap();
                assert_eq!(next, [0, 127, 0, 0, 2, 0, 54, 0, 0]);
                assert_eq!(decoded.read(&mut [0]).await.unwrap(), 0);
            });
            let mut next = packet(0);
            next.remote = Destination::Ip("127.0.0.2:54".parse().unwrap());
            tokio::time::timeout(Duration::from_secs(2), association.send(next))
                .await
                .unwrap()
                .unwrap();
            outbound.shutdown().await;
            tokio::time::timeout(Duration::from_secs(1), decoding)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

#[tokio::test]
async fn all_ciphers_preserve_budget_edges_and_fragmented_receive_cancellation() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("UOT-SS", "budget_read_cancel");
    for cipher in CIPHERS {
        let (outbound, peer) = fixture(cipher, 4096);
        let mut association = outbound
            .open_datagram(
                request().with_budget(DatagramBudget::new(65_535, 8)),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        assert!(association.supports_shared_destinations());
        assert!(association.send(packet(65_536)).await.is_err());
        let (ready, arrived) = tokio::sync::oneshot::channel();
        let (resume, proceed) = tokio::sync::oneshot::channel();
        let decoding = tokio::spawn(async move {
            let mut decoded = decoder(peer, cipher);
            assert_eq!(
                decoded.handshake().await.unwrap(),
                ("sp.v2.udp-over-tcp.arpa".to_owned(), 0).into()
            );
            let mut request = [0; 17];
            for byte in &mut request {
                *byte = decoded.read_u8().await.unwrap();
            }
            assert_eq!(
                request,
                [0, 1, 127, 0, 0, 1, 0, 53, 0, 127, 0, 0, 1, 0, 53, 255, 255]
            );
            let mut payload = vec![0; 65_535];
            decoded.read_exact(&mut payload).await.unwrap();
            assert!(payload.iter().all(|b| *b == 7));
            // Coalesced oversize response then a partial valid response. The
            // caller's cancelled receive must not lose either parser position.
            decoded
                .write_all(b"\x00\x7f\x00\x00\x01\x00\x35\x00\x09oversized\x00\x7f")
                .await
                .unwrap();
            decoded.flush().await.unwrap();
            ready.send(()).unwrap();
            proceed.await.unwrap();
            for b in b"\x00\x00\x02\x00\x36\x00\x02ok" {
                decoded.write_all(&[*b]).await.unwrap();
                decoded.flush().await.unwrap();
            }
            assert_eq!(decoded.read(&mut [0; 1]).await.unwrap(), 0);
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            association.send(packet(65_535)).await.unwrap();
            arrived.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), association.receive())
                    .await
                    .is_err()
            );
            resume.send(()).unwrap();
            let response = association.receive().await.unwrap();
            assert_eq!(
                response.remote,
                Destination::Ip("127.0.0.2:54".parse().unwrap())
            );
            assert_eq!(response.payload.as_ref(), b"ok");
            outbound.shutdown().await;
            decoding.await.unwrap();
        })
        .await
        .unwrap();
    }
}

struct ControlledResolver {
    calls: std::sync::atomic::AtomicUsize,
    pending: bool,
}

#[async_trait]
impl vole::dialer::Resolver for ControlledResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> std::io::Result<vole::dialer::ResolvedEndpoint> {
        assert_eq!(host, "dns.test", "only the business name may be resolved");
        assert_eq!(port, 53);
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.pending {
            std::future::pending::<()>().await;
        }
        Ok(vole::dialer::ResolvedEndpoint {
            logical_host: host.into(),
            port,
            addresses: vec!["127.0.0.1:53".parse().unwrap()],
        })
    }
}

#[tokio::test]
async fn domains_use_only_the_supplied_resolver_and_stop_cancels_pending_dns() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("UOT-SS", "dns");
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vole::dns::resolution::ResolutionContext;
    let mut datagram = packet(0);
    datagram.remote = Destination::domain("dns.test", 53).unwrap();
    let (outbound, mut peer) = fixture(CIPHERS[0], 4096);
    let mut association = outbound
        .open_datagram(request(), &EstablishContext::default())
        .await
        .unwrap();
    assert!(association.send(datagram.clone()).await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(10), peer.read_u8())
            .await
            .is_err()
    );
    outbound.shutdown().await;
    for pending in [false, true] {
        let resolver = Arc::new(ControlledResolver {
            calls: AtomicUsize::new(0),
            pending,
        });
        let context = EstablishContext::with_resolution(
            Duration::from_secs(2),
            ResolutionContext::measurement(resolver.clone(), true),
        );
        let (outbound, peer) = fixture(CIPHERS[0], 4096);
        let mut association = outbound.open_datagram(request(), &context).await.unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        if pending {
            let (sent, ()) = tokio::join!(association.send(datagram.clone()), async {
                while resolver.calls.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
                outbound.shutdown().await;
            });
            assert!(sent.is_err());
        } else {
            association.send(datagram.clone()).await.unwrap();
            let mut decoded = decoder(peer, CIPHERS[0]);
            assert_eq!(
                decoded.handshake().await.unwrap(),
                ("sp.v2.udp-over-tcp.arpa".to_owned(), 0).into()
            );
            let mut wire = [0; 17];
            decoded.read_exact(&mut wire).await.unwrap();
            assert_eq!(
                wire,
                [0, 1, 127, 0, 0, 1, 0, 53, 0, 127, 0, 0, 1, 0, 53, 0, 0]
            );
            outbound.shutdown().await;
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }
}

#[cfg(feature = "interop-test")]
#[tokio::test]
async fn stop_joins_a_full_receiver_and_releases_io_with_the_association_retained() {
    let _case = vole::resources::case_events::Case::new("UOT-SS", "stop_full_queue");
    let probe = vole::resources::observation::ResourceProbe::default();
    let (outbound, peer) = fixture(CIPHERS[0], 4096);
    let mut association = probe
        .scope(outbound.open_datagram(request(), &EstablishContext::default()))
        .await
        .unwrap();
    let (ready, arrived) = tokio::sync::oneshot::channel();
    let producer = tokio::spawn(async move {
        let mut decoded = decoder(peer, CIPHERS[0]);
        decoded.handshake().await.unwrap();
        let mut first = [0; 17];
        decoded.read_exact(&mut first).await.unwrap();
        let frame = [
            b"\x00\x7f\x00\x00\x01\x00\x35\x01\x00".as_slice(),
            &[7; 256],
        ]
        .concat();
        for _ in 0..4 {
            decoded.write_all(&frame).await.unwrap();
            decoded.flush().await.unwrap();
        }
        ready.send(()).unwrap();
        for _ in 0..64 {
            if decoded.write_all(&frame).await.is_err() || decoded.flush().await.is_err() {
                return;
            }
        }
        panic!("unconsumed replies exceeded the bounded reader and memory IO");
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        association.send(packet(0)).await.unwrap();
        arrived.await.unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(!probe.snapshot().is_idle());
        outbound.shutdown().await;
        // This caller intentionally retains the closed logical handle. Its
        // object guard is not a live read task or an owned physical stream.
        use vole::resources::observation::ResourceKind;
        assert_eq!(probe.snapshot().current(ResourceKind::Task), 0);
        assert_eq!(probe.snapshot().current(ResourceKind::Association), 1);
        assert!(association.receive().await.is_err());
        assert!(association.send(packet(0)).await.is_err());
        producer.await.unwrap();
        drop(association);
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn zero_length_first_datagram_initializes_ss_once_without_an_empty_write() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("UOT-SS", "first_packet");
    let config = Config::parse_yaml(br#"
mixed-port: 1080
proxies:
  - {name: ss, type: ss, server: fixture.invalid, port: 443, cipher: 2022-blake3-aes-128-gcm, password: BwcHBwcHBwcHBwcHBwcHBw==, udp: true, udp-over-tcp: true}
rules: ['MATCH,ss']
"#).expect("SS UoT v2 configuration");
    let ProxyProtocol::Shadowsocks(config) = &config.proxies[0].protocol else {
        panic!("wrong protocol")
    };
    let (raw, mut peer) = tokio::io::duplex(4096);
    let outbound = ShadowsocksOutbound::new_with_path(
        config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(raw)))))),
    )
    .unwrap();
    let mut association = outbound
        .open_datagram(
            DatagramRequest::new(DatagramSession::new(
                InboundKind::Socks5,
                "127.0.0.1:1234".parse().unwrap(),
            )),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), association.receive())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), peer.read_u8())
            .await
            .is_err(),
        "background reading emitted an empty SS handshake"
    );
    let decoder = tokio::spawn(async move {
        let mut decoded = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            peer,
            "2022-blake3-aes-128-gcm".parse().unwrap(),
            &[7; 16],
        );
        let target = decoded.handshake().await.unwrap();
        assert_eq!(target, ("sp.v2.udp-over-tcp.arpa".to_owned(), 0).into());
        let mut first = [0; 17];
        decoded.read_exact(&mut first).await.unwrap();
        // Request uses SOCKS ATYP=1; datagram uses UoT ATYP=0. Empty UDP is
        // still a nonempty encrypted first write accepted by the strict codec.
        assert_eq!(
            first,
            [0, 1, 127, 0, 0, 1, 0, 53, 0, 127, 0, 0, 1, 0, 53, 0, 0]
        );
        decoded.write_all(&first[8..]).await.unwrap();
        decoded.flush().await.unwrap();
        let mut next = [0; 13];
        decoded.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"\x00\x7f\x00\x00\x01\x00\x35\x00\x04next");
        decoded.write_all(&next).await.unwrap();
        decoded.flush().await.unwrap();
        assert_eq!(decoded.read(&mut [0; 1]).await.unwrap(), 0);
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        for payload in [b"".as_slice(), b"next"] {
            let datagram = Datagram {
                remote: Destination::Ip("127.0.0.1:53".parse().unwrap()),
                payload: Bytes::copy_from_slice(payload),
                sniffed_domain: None,
            };
            association.send(datagram.clone()).await.unwrap();
            let response = association.receive().await.unwrap();
            assert_eq!(response.remote, datagram.remote);
            assert_eq!(response.payload, datagram.payload);
        }
        association.close().await.unwrap();
        outbound.shutdown().await;
        decoder.await.unwrap();
    })
    .await
    .unwrap();
}
