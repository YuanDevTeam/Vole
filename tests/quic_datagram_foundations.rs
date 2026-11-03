#![cfg(feature = "quic-transport")]

use quinn::AsyncUdpSocket;
use std::{future::poll_fn, io::IoSliceMut, time::Duration};
use vole::{
    dialer::Dialer,
    dispatch::DatagramBudget,
    outbound::{DatagramRequest, DirectOutbound, EstablishContext, OutboundConnector},
    session::{DatagramSession, InboundKind},
    transport::quic::attach,
};

#[tokio::test]
async fn quic_minimum_budget_is_checked_before_io_and_exact_minimum_connects() {
    use std::sync::Arc;
    tokio::time::timeout(Duration::from_secs(10), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = certificate.cert.der().clone();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            assert_eq!(receive.read_to_end(64).await.unwrap(), b"request");
            send.write_all(b"response-after-fin").await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
            connection.closed().await;
            server.close(0u32.into(), b"");
            server.wait_idle().await;
        });
        let open = || async {
            DirectOutbound::new(Dialer::default())
                .open_datagram(
                    DatagramRequest::new(DatagramSession::new(
                        InboundKind::InternalMeasure,
                        address,
                    )),
                    &EstablishContext::default(),
                )
                .await
                .unwrap()
        };
        assert!(attach(open().await, address, DatagramBudget::new(1199, 1200)).is_err());
        assert!(attach(open().await, address, DatagramBudget::new(1200, 1199)).is_err());
        let (socket, driver) =
            attach(open().await, address, DatagramBudget::new(1200, 1200)).unwrap();
        assert_eq!(socket.budget().quic_payload_limit().unwrap(), 1200);
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.max_udp_payload_size(1200).unwrap();
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client_config =
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(None)
            .max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()));
        client_config.transport_config(Arc::new(transport));
        client.set_default_client_config(client_config);
        let connection = client.connect(address, "localhost").unwrap().await.unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        send.write_all(b"request").await.unwrap();
        send.finish().unwrap();
        assert_eq!(
            receive.read_to_end(64).await.unwrap(),
            b"response-after-fin"
        );
        assert!(socket.stats().sent > 0 && socket.stats().received > 0);
        connection.close(0u32.into(), b"");
        client.close(0u32.into(), b"");
        client.wait_idle().await;
        driver.stop().await.unwrap();
        server_task.await.unwrap();
    })
    .await
    .unwrap();
}

struct PendingSend {
    starts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    closed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    entered: std::sync::Arc<tokio::sync::Notify>,
}
#[async_trait::async_trait]
impl vole::dispatch::DatagramTransport for PendingSend {
    fn supports_shared_destinations(&self) -> bool {
        false
    }

    async fn send(
        &mut self,
        _: vole::session::Datagram,
    ) -> Result<(), vole::dispatch::DispatchError> {
        self.starts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.entered.notify_one();
        std::future::pending().await
    }
    async fn receive(&mut self) -> Result<vole::session::Datagram, vole::dispatch::DispatchError> {
        std::future::pending().await
    }
    async fn close(&mut self) -> Result<(), vole::dispatch::DispatchError> {
        self.closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::test]
async fn pending_send_is_not_restarted_and_stop_cancels_without_waiting_for_writable() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let starts = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let peer = "127.0.0.1:443".parse().unwrap();
    let (socket, driver) = attach(
        Box::new(PendingSend {
            starts: starts.clone(),
            closed: closed.clone(),
            entered: entered.clone(),
        }),
        peer,
        DatagramBudget::new(1400, 1400),
    )
    .unwrap();
    let packet = quinn::udp::Transmit {
        destination: peer,
        ecn: None,
        contents: b"pending",
        segment_size: None,
        src_ip: None,
    };
    socket.try_send(&packet).unwrap();
    entered.notified().await;
    for _ in 0..32 {
        socket.try_send(&packet).unwrap();
    }
    assert_eq!(
        socket.try_send(&packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    tokio::task::yield_now().await;
    assert_eq!(starts.load(Ordering::Relaxed), 1);
    tokio::time::timeout(Duration::from_secs(2), driver.stop())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(starts.load(Ordering::Relaxed), 1);
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    assert!(socket.try_send(&packet).is_err());
}

#[tokio::test]
async fn controlled_quic_datagram_seam_roundtrips_and_stop_closes_owned_io() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let request = DatagramRequest::new(DatagramSession::new(InboundKind::Socks5, address))
            .with_budget(DatagramBudget::new(1400, 1400));
        let transport = DirectOutbound::new(Dialer::default())
            .open_datagram(request, &EstablishContext::default())
            .await
            .unwrap();
        let (socket, owner) = attach(transport, address, DatagramBudget::new(1400, 1400)).unwrap();
        socket
            .try_send(&quinn::udp::Transmit {
                destination: address,
                ecn: None,
                contents: b"first",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let mut bytes = [0; 1401];
        let (length, source) = peer.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"first");
        peer.send_to(b"reply", source).await.unwrap();
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        assert_eq!(
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                .await
                .unwrap(),
            1
        );
        assert_eq!(&buffers[0][..meta[0].len], b"reply");
        assert_eq!(meta[0].addr, address);
        owner.stop().await.unwrap();
        assert!(
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: address,
                    ecn: None,
                    contents: b"after-stop",
                    segment_size: None,
                    src_ip: None
                })
                .is_err()
        );
        assert!(
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn mapped_peer_sends_to_one_physical_port_and_reports_the_logical_peer() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let logical = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let physical = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical_peer = logical.local_addr().unwrap();
        let physical_peer = physical.local_addr().unwrap();
        let transport = DirectOutbound::new(Dialer::default())
            .open_datagram(
                DatagramRequest::new(DatagramSession::new(InboundKind::Socks5, logical_peer))
                    .with_max_response_payload_size(1400),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        let (socket, driver) = vole::transport::quic::attach_mapped(
            transport,
            logical_peer,
            physical_peer,
            DatagramBudget::new(1400, 1400),
        )
        .unwrap();
        socket
            .try_send(&quinn::udp::Transmit {
                destination: logical_peer,
                ecn: None,
                contents: b"mapped",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let mut payload = [0; 1400];
        let (len, source) = physical.recv_from(&mut payload).await.unwrap();
        assert_eq!(&payload[..len], b"mapped");
        logical
            .send_to(b"not-the-physical-peer", source)
            .await
            .unwrap();
        while socket.stats().rejected_source == 0 {
            tokio::task::yield_now().await;
        }
        physical.send_to(b"mapped-reply", source).await.unwrap();
        let mut buffers = [IoSliceMut::new(&mut payload)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
            .await
            .unwrap();
        assert_eq!(meta[0].addr, logical_peer);
        assert_eq!(&buffers[0][..meta[0].len], b"mapped-reply");
        driver.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn incoming_queue_backpressures_without_discarding_a_controlled_burst() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = echo.local_addr().unwrap();
        let transport = DirectOutbound::new(Dialer::default())
            .open_datagram(
                DatagramRequest::new(DatagramSession::new(InboundKind::Socks5, peer))
                    .with_max_response_payload_size(1400),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        let (socket, driver) = attach(transport, peer, DatagramBudget::new(1400, 1400)).unwrap();
        socket
            .try_send(&quinn::udp::Transmit {
                destination: peer,
                ecn: None,
                contents: b"ready",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let mut payload = [0; 1400];
        let (_, source) = echo.recv_from(&mut payload).await.unwrap();
        for sequence in 0..40_u8 {
            echo.send_to(&[sequence], source).await.unwrap();
        }
        // Deliberately pause the reader until the bounded queue saturates.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            socket.stats().peak_incoming,
            vole::transport::quic::QUEUE_LIMIT
        );
        assert_eq!(socket.stats().dropped_full, 0);
        for expected in 0..40_u8 {
            let mut buffers = [IoSliceMut::new(&mut payload)];
            let mut meta = [quinn::udp::RecvMeta::default()];
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                .await
                .unwrap();
            assert_eq!(&buffers[0][..meta[0].len], &[expected]);
        }
        driver.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn controlled_direct_datagrams_roundtrip_and_stop() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = echo.local_addr().unwrap();
        let transport = DirectOutbound::new(Dialer::default())
            .open_datagram(
                DatagramRequest::new(DatagramSession::new(
                    InboundKind::Socks5,
                    "127.0.0.1:0".parse().unwrap(),
                ))
                .with_max_response_payload_size(1400),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        let (socket, driver) = attach(transport, peer, DatagramBudget::new(1400, 1400)).unwrap();
        socket
            .try_send(&quinn::udp::Transmit {
                destination: peer,
                ecn: None,
                contents: b"controlled-datagram",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let mut payload = [0; 1400];
        let (len, source) = echo.recv_from(&mut payload).await.unwrap();
        assert_eq!(&payload[..len], b"controlled-datagram");
        let foreign = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        foreign.send_to(b"wrong-source", source).await.unwrap();
        while socket.stats().rejected_source == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: foreign.local_addr().unwrap(),
                    ecn: None,
                    contents: b"wrong-target",
                    segment_size: None,
                    src_ip: None,
                })
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: &[0; 1401],
                    segment_size: None,
                    src_ip: None,
                })
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        echo.send_to(b"reply", source).await.unwrap();
        let mut buffers = [IoSliceMut::new(&mut payload)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        assert_eq!(
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                .await
                .unwrap(),
            1
        );
        assert_eq!(meta[0].addr, peer);
        assert_eq!(&buffers[0][..meta[0].len], b"reply");
        // The current-thread driver cannot consume these until we yield.
        let transmit = quinn::udp::Transmit {
            destination: peer,
            ecn: None,
            contents: b"bounded",
            segment_size: None,
            src_ip: None,
        };
        for _ in 0..vole::transport::quic::QUEUE_LIMIT {
            socket.try_send(&transmit).unwrap();
        }
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut writable = socket.clone().create_io_poller();
        let waker = futures_util::task::noop_waker();
        assert!(
            writable
                .as_mut()
                .poll_writable(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        assert_eq!(
            socket.stats().peak_outgoing,
            vole::transport::quic::QUEUE_LIMIT
        );
        driver.stop().await.unwrap();
        assert!(
            socket
                .try_send(&quinn::udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: b"after-stop",
                    segment_size: None,
                    src_ip: None
                })
                .is_err()
        );
    })
    .await
    .unwrap();
}
