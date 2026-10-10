use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole_netstack::{
    ClientAddresses, NetStack, NetStackConfig, NetStackError, Packet, UdpDatagram,
};

const WAIT: Duration = Duration::from_secs(2);

fn client_addresses() -> ClientAddresses {
    ClientAddresses {
        ipv4: Some("10.23.0.2".parse().unwrap()),
        ipv6: Some("fd23::2".parse().unwrap()),
    }
}

fn tcp_flow(packet: &Packet) -> Flow {
    let bytes = packet.data();
    let offset = ip_header_len(bytes);
    let (source, destination) = match bytes[0] >> 4 {
        4 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap()).into(),
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).unwrap()).into(),
        ),
        6 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap()).into(),
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap()).into(),
        ),
        _ => unreachable!(),
    };
    Flow {
        source: SocketAddr::new(
            source,
            u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap()),
        ),
        destination: SocketAddr::new(
            destination,
            u16::from_be_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()),
        ),
    }
}

async fn wait_no_tcp(stats: &vole_netstack::NetStackStats) {
    tokio::time::timeout(WAIT, async {
        while stats.snapshot().active_tcp != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TCP state was not reclaimed");
    assert_eq!(stats.snapshot().half_open_tcp, 0);
}

async fn timeout_tcp_flag(stream: &mut vole_netstack::PacketStream, flag: u8) -> Packet {
    loop {
        let packet = timeout_packet(stream).await;
        let offset = ip_header_len(packet.data());
        if packet.data()[offset + 13] & flag != 0 {
            return packet;
        }
    }
}

#[tokio::test]
async fn active_tcp_uses_configured_sources_and_delivers_established_duplex_streams() {
    let mut parts = NetStack::start_client(NetStackConfig::default(), client_addresses()).unwrap();
    for destination in ["198.51.100.20:443", "[2001:db8:2::20]:443"] {
        let destination: SocketAddr = destination.parse().unwrap();
        let mut connect = Box::pin(
            parts
                .tcp_connector
                .connect(destination, tokio::time::Instant::now() + WAIT),
        );
        assert!(futures_util::poll!(connect.as_mut()).is_pending());
        let syn = timeout_packet(&mut parts.packet_stream).await;
        let flow = tcp_flow(&syn);
        assert_eq!(flow.destination, destination);
        assert_eq!(
            flow.source.ip(),
            if destination.is_ipv4() {
                IpAddr::V4(client_addresses().ipv4.unwrap())
            } else {
                IpAddr::V6(client_addresses().ipv6.unwrap())
            }
        );
        let offset = ip_header_len(syn.data());
        assert_eq!(
            syn.data()[offset + 13] & (TcpFlags::SYN | TcpFlags::ACK),
            TcpFlags::SYN
        );
        assert!(
            futures_util::poll!(connect.as_mut()).is_pending(),
            "connect returned before the handshake"
        );
        let peer = Flow {
            source: flow.destination,
            destination: flow.source,
        };
        let local_sequence = tcp_sequence(&syn).wrapping_add(1);
        parts
            .packet_sink
            .send(build_tcp(
                &peer,
                800,
                local_sequence,
                TcpFlags::SYN | TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut stream = tokio::time::timeout(WAIT, connect).await.unwrap().unwrap();
        assert_eq!(stream.source_addr(), flow.source);
        assert_eq!(stream.destination_addr(), destination);
        assert_eq!(parts.stats.snapshot().half_open_tcp, 0);
        stream.write_all(b"hello").await.unwrap();
        loop {
            let packet = timeout_packet(&mut parts.packet_stream).await;
            let offset = ip_header_len(packet.data());
            let start = offset + usize::from(packet.data()[offset + 12] >> 4) * 4;
            if start != packet.len() {
                assert_eq!(&packet.data()[start..], b"hello");
                assert_eq!(tcp_flow(&packet).source, flow.source);
                break;
            }
        }
        parts
            .packet_sink
            .send(build_tcp(
                &peer,
                801,
                local_sequence.wrapping_add(5),
                TcpFlags::ACK,
                b"world",
            ))
            .await
            .unwrap();
        let mut payload = [0; 5];
        tokio::time::timeout(WAIT, stream.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload, b"world");
        stream.shutdown().await.unwrap();
        timeout_tcp_flag(&mut parts.packet_stream, 1).await;
        parts
            .packet_sink
            .send(build_tcp(
                &peer,
                806,
                local_sequence.wrapping_add(6),
                TcpFlags::ACK | 1,
                b"tail",
            ))
            .await
            .unwrap();
        let mut tail = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, b"tail");
    }
    parts.control.stop().await;
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn active_tcp_refused_handshake_reclaims_its_socket() {
    let mut parts = NetStack::start_client(NetStackConfig::default(), client_addresses()).unwrap();
    let mut connect = Box::pin(parts.tcp_connector.connect(
        "198.51.100.20:443".parse().unwrap(),
        tokio::time::Instant::now() + WAIT,
    ));
    assert!(futures_util::poll!(connect.as_mut()).is_pending());
    let syn = timeout_packet(&mut parts.packet_stream).await;
    let flow = tcp_flow(&syn);
    let peer = Flow {
        source: flow.destination,
        destination: flow.source,
    };
    parts
        .packet_sink
        .send(build_tcp(
            &peer,
            0,
            tcp_sequence(&syn).wrapping_add(1),
            TcpFlags::ACK | 4,
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, connect)
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::ConnectionRefused
    );
    wait_no_tcp(&parts.stats).await;
    parts.control.stop().await;
}

#[tokio::test]
async fn active_tcp_cancel_and_deadline_emit_reset_and_reclaim_state() {
    for (drop_future, establish) in [(true, false), (false, false), (true, true)] {
        let mut parts = NetStack::start_client(
            NetStackConfig {
                max_poll_interval: Duration::from_secs(5),
                ..NetStackConfig::default()
            },
            client_addresses(),
        )
        .unwrap();
        let mut connect = Box::pin(parts.tcp_connector.connect(
            "198.51.100.20:443".parse().unwrap(),
            tokio::time::Instant::now() + Duration::from_millis(150),
        ));
        assert!(futures_util::poll!(connect.as_mut()).is_pending());
        let syn = timeout_packet(&mut parts.packet_stream).await;
        if establish {
            let flow = tcp_flow(&syn);
            let peer = Flow {
                source: flow.destination,
                destination: flow.source,
            };
            parts
                .packet_sink
                .send(build_tcp(
                    &peer,
                    800,
                    tcp_sequence(&syn).wrapping_add(1),
                    TcpFlags::SYN | TcpFlags::ACK,
                    &[],
                ))
                .await
                .unwrap();
            timeout_tcp_flag(&mut parts.packet_stream, TcpFlags::ACK).await;
            tokio::time::timeout(WAIT, async {
                while parts.stats.snapshot().half_open_tcp != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            // The caller has not polled the queued Established result. Drop
            // must still abort, rather than leaving an unclaimed live socket.
        }
        if drop_future {
            drop(connect);
        } else {
            assert_eq!(
                connect.await.unwrap_err().kind(),
                std::io::ErrorKind::TimedOut
            );
        }
        let reset = timeout_packet(&mut parts.packet_stream).await;
        let offset = ip_header_len(reset.data());
        assert_ne!(reset.data()[offset + 13] & 4, 0);
        assert_eq!(tcp_flow(&reset).source, tcp_flow(&syn).source);
        wait_no_tcp(&parts.stats).await;
        parts.control.stop().await;
    }
}

#[tokio::test]
async fn active_tcp_stop_releases_full_output_pending_connects_and_rejects_unsolicited_syn() {
    let mut parts = NetStack::start_client(
        NetStackConfig {
            packet_queue: 1,
            max_poll_interval: Duration::from_secs(5),
            ..NetStackConfig::default()
        },
        client_addresses(),
    )
    .unwrap();
    let destination = "198.51.100.20:443".parse().unwrap();
    let mut first = Box::pin(
        parts
            .tcp_connector
            .connect(destination, tokio::time::Instant::now() + WAIT),
    );
    let mut second = Box::pin(
        parts
            .tcp_connector
            .connect(destination, tokio::time::Instant::now() + WAIT),
    );
    assert!(futures_util::poll!(first.as_mut()).is_pending());
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    let stranger = Flow {
        source: destination,
        destination: "10.23.0.2:8000".parse().unwrap(),
    };
    parts
        .packet_sink
        .send(build_tcp(&stranger, 100, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    tokio::time::timeout(WAIT, async {
        while parts.stats.snapshot().active_tcp != 2 || parts.stats.snapshot().rejected_tcp != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // The sole output slot still contains a SYN; stop must not await draining.
    tokio::time::timeout(Duration::from_millis(500), parts.control.stop())
        .await
        .unwrap();
    assert_eq!(
        first.await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        second.await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    wait_no_tcp(&parts.stats).await;
    assert!(parts.packet_stream.recv().await.is_none());
    assert!(matches!(
        parts
            .packet_sink
            .try_send(build_tcp(&stranger, 100, 0, TcpFlags::SYN, &[])),
        Err(NetStackError::Stopped)
    ));
}

#[tokio::test]
async fn ready_tcp_burst_preserves_flow_binding_and_neighboring_icmp() {
    let mut parts = NetStack::start(NetStackConfig {
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap()
    .into_parts();
    let flows = [Flow::v4(11_000), Flow::v4(11_001), Flow::v6(11_002)];
    // Queue the whole burst before yielding to the driver. The two IPv4 SYNs
    // share a listen endpoint but must retain separate source/stream bindings.
    for flow in &flows {
        parts
            .packet_sink
            .try_send(build_tcp(flow, 100, 0, TcpFlags::SYN, &[]))
            .unwrap();
    }
    parts
        .packet_sink
        .try_send(build_icmpv4_echo(b"tcp-neighbor"))
        .unwrap();
    let mut server_sequences = [None; 3];
    let mut echo = false;
    for _ in 0..4 {
        let reply = timeout_packet(&mut parts.packet_stream).await;
        if let Some(index) = flows.iter().position(|flow| is_syn_ack(&reply, flow)) {
            assert!(
                server_sequences[index]
                    .replace(tcp_sequence(&reply))
                    .is_none()
            );
        } else {
            let offset = ip_header_len(reply.data());
            assert_eq!(reply.data()[9], 1);
            assert_eq!(reply.data()[offset], 0);
            assert_eq!(&reply.data()[offset + 8..], b"tcp-neighbor");
            assert!(!echo);
            echo = true;
        }
    }
    assert!(echo);
    let mut streams = Vec::new();
    for _ in &flows {
        streams.push(parts.tcp_listener.accept().await.unwrap());
    }
    for (index, flow) in flows.iter().enumerate() {
        parts
            .packet_sink
            .try_send(build_tcp(
                flow,
                101,
                server_sequences[index].unwrap().wrapping_add(1),
                TcpFlags::ACK,
                &[u8::try_from(index).unwrap()],
            ))
            .unwrap();
    }
    for mut stream in streams {
        let index = flows
            .iter()
            .position(|flow| flow.source == stream.source_addr())
            .unwrap();
        assert_eq!(stream.destination_addr(), flows[index].destination);
        let mut byte = [0];
        tokio::time::timeout(WAIT, stream.read_exact(&mut byte))
            .await
            .expect("batched TCP payload was not delivered")
            .unwrap();
        assert_eq!(byte, [u8::try_from(index).unwrap()]);
    }
    assert_eq!(parts.stats.snapshot().icmp_dropped, 0);
    parts.control.stop().await;
}

#[tokio::test]
async fn configured_jumbo_mtu_reaches_tcp_mss_for_both_ip_families() {
    let mut parts = NetStack::start_tcp(NetStackConfig {
        mtu: 9000,
        ..NetStackConfig::default()
    })
    .unwrap();
    for flow in [Flow::v4(12000), Flow::v6(12001)] {
        parts
            .packet_sink
            .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let reply = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&reply, &flow));
        let offset = ip_header_len(reply.data());
        let header_len = usize::from(reply.data()[offset + 12] >> 4) * 4;
        let mut options = &reply.data()[offset + 20..offset + header_len];
        let mut mss = None;
        while let Some(kind) = options.first().copied() {
            match kind {
                0 => break,
                1 => options = &options[1..],
                _ => {
                    let length = usize::from(options[1]);
                    assert!(length >= 2 && length <= options.len());
                    if kind == 2 {
                        assert_eq!(length, 4);
                        mss = Some(u16::from_be_bytes([options[2], options[3]]));
                    }
                    options = &options[length..];
                }
            }
        }
        assert_eq!(mss, Some(u16::try_from(9000 - offset - 20).unwrap()));
    }
    parts.control.stop().await;
}

#[tokio::test]
async fn synthetic_tun_supports_ipv4_and_ipv6_tcp_and_udp() {
    let stack = NetStack::start(NetStackConfig::default()).unwrap();
    let mut parts = stack.into_parts();
    let mut streams = Vec::new();

    for flow in [Flow::v4(12_000), Flow::v6(12_001)] {
        parts
            .packet_sink
            .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let reply = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&reply, &flow));
        let stream = tokio::time::timeout(WAIT, parts.tcp_listener.accept())
            .await
            .expect("TCP accept timed out")
            .expect("TCP listener stopped");
        assert_eq!(stream.source_addr(), flow.source);
        assert_eq!(stream.destination_addr(), flow.destination);
        streams.push(stream);
    }

    for flow in [Flow::v4(13_000), Flow::v6(13_001)] {
        let payload = Bytes::from_static(b"synthetic-tun-udp");
        parts
            .packet_sink
            .send(build_udp(&flow, &payload))
            .await
            .unwrap();
        let datagram = tokio::time::timeout(WAIT, parts.udp_socket.recv())
            .await
            .expect("UDP receive timed out")
            .expect("UDP socket stopped");
        assert_eq!(datagram.source, flow.source);
        assert_eq!(datagram.destination, flow.destination);
        assert_eq!(datagram.payload, payload);

        let response = UdpDatagram::new(flow.destination, flow.source, b"reply".as_slice());
        parts.udp_socket.send(response.clone()).await.unwrap();
        let raw_response = timeout_packet(&mut parts.packet_stream).await;
        assert_udp_packet(&raw_response, &response);
    }

    parts.control.stop().await;
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn tcp_only_mode_keeps_tcp_icmp_and_stop_without_a_udp_queue() {
    let mut parts = NetStack::start_tcp(NetStackConfig {
        // Would exceed Tokio's channel capacity limit if a UDP queue existed.
        udp_queue: usize::MAX,
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let flow = Flow::v4(13_100);
    parts
        .packet_sink
        .send(build_udp(&flow, b"handled-by-caller"))
        .await
        .unwrap();
    parts
        .packet_sink
        .send(build_icmpv4_echo(b"tcp-only"))
        .await
        .unwrap();
    let echo = timeout_packet(&mut parts.packet_stream).await;
    assert_eq!(&echo.data()[28..], b"tcp-only");
    parts
        .packet_sink
        .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    assert!(is_syn_ack(
        &timeout_packet(&mut parts.packet_stream).await,
        &flow
    ));
    let stream = parts.tcp_listener.accept().await.unwrap();
    assert_eq!(stream.source_addr(), flow.source);
    assert_eq!(parts.stats.snapshot().dropped_udp, 0);
    parts.control.stop().await;
    assert!(parts.packet_stream.recv().await.is_none());
    assert!(stream.is_stopped());
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn output_capacity_recovery_wakes_a_pending_tcp_reset_before_its_timer() {
    for flow in [Flow::v4(13_200), Flow::v6(13_201)] {
        let mut parts = NetStack::start(NetStackConfig {
            packet_queue: 1,
            max_poll_interval: Duration::from_secs(5),
            ..NetStackConfig::default()
        })
        .unwrap()
        .into_parts();
        parts
            .packet_sink
            .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&syn_ack, &flow));
        let stream = parts.tcp_listener.accept().await.unwrap();

        // Fill the sole raw output queue before asking smoltcp to emit RST.
        let blocker = UdpDatagram::new(flow.destination, flow.source, b"blocker".as_slice());
        parts.udp_socket.send(blocker.clone()).await.unwrap();
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(parts.stats.snapshot().active_tcp, 1);

        let queued = parts.packet_stream.try_recv().unwrap();
        assert_udp_packet(&queued, &blocker);
        let reset = tokio::time::timeout(Duration::from_millis(500), parts.packet_stream.recv())
            .await
            .expect("output capacity recovery did not wake the driver")
            .unwrap();
        let offset = ip_header_len(reset.data());
        assert_ne!(reset.data()[offset + 13] & 0x04, 0, "missing TCP RST");
        tokio::time::timeout(WAIT, async {
            while parts.stats.snapshot().active_tcp != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reset flow was not reclaimed");
        assert!(parts.packet_stream.try_recv().is_err());
        parts.control.stop().await;
    }
}

#[tokio::test]
async fn tcp_only_full_output_retains_one_pending_syn_and_stops_without_draining() {
    for recover_capacity in [false, true] {
        let mut parts = NetStack::start_tcp(NetStackConfig {
            packet_queue: 1,
            fake_icmp_echo: true,
            max_poll_interval: Duration::from_secs(5),
            ..NetStackConfig::default()
        })
        .unwrap();
        let flow = Flow::v4(13_300);
        parts
            .packet_sink
            .send(build_icmpv4_echo(b"blocker"))
            .await
            .unwrap();
        parts
            .packet_sink
            .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let stream = tokio::time::timeout(WAIT, parts.tcp_listener.accept())
            .await
            .expect("SYN was not retained behind full output")
            .unwrap();
        assert_eq!(parts.stats.snapshot().active_tcp, 1);
        assert_eq!(parts.stats.snapshot().rejected_tcp, 0);
        if recover_capacity {
            let echo = parts.packet_stream.try_recv().unwrap();
            assert_eq!(&echo.data()[28..], b"blocker");
            let syn_ack =
                tokio::time::timeout(Duration::from_millis(500), parts.packet_stream.recv())
                    .await
                    .expect("pending SYN did not resume when output capacity returned")
                    .unwrap();
            assert!(is_syn_ack(&syn_ack, &flow));
        }
        tokio::time::timeout(Duration::from_millis(500), parts.control.stop())
            .await
            .expect("full output or pending ingress blocked stop");
        assert!(stream.is_stopped());
        assert_eq!(parts.stats.snapshot().active_tcp, 0);
        assert!(parts.packet_stream.recv().await.is_none());
    }
}

#[tokio::test]
async fn dropping_the_only_output_consumer_stops_active_tcp_and_other_endpoints() {
    let mut parts = NetStack::start(NetStackConfig {
        max_poll_interval: Duration::from_secs(5),
        ..NetStackConfig::default()
    })
    .unwrap()
    .into_parts();
    let flow = Flow::v4(13_400);
    parts
        .packet_sink
        .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    assert!(is_syn_ack(
        &timeout_packet(&mut parts.packet_stream).await,
        &flow
    ));
    let stream = parts.tcp_listener.accept().await.unwrap();
    assert_eq!(parts.stats.snapshot().active_tcp, 1);

    drop(parts.packet_stream);
    tokio::time::timeout(Duration::from_millis(500), parts.control.wait_stopped())
        .await
        .expect("closed output did not stop the driver promptly");
    assert!(stream.is_stopped());
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
    assert!(parts.tcp_listener.accept().await.is_none());
    assert!(parts.udp_socket.recv().await.is_none());
    assert!(matches!(
        parts
            .packet_sink
            .try_send(build_tcp(&flow, 101, 1, TcpFlags::ACK, &[])),
        Err(NetStackError::Stopped)
    ));
    assert_eq!(
        parts
            .udp_socket
            .send(UdpDatagram::new(
                flow.destination,
                flow.source,
                b"stopped".as_slice(),
            ))
            .await,
        Err(vole_netstack::UdpError::Stopped)
    );
}

#[tokio::test]
async fn asymmetric_tcp_buffers_bound_each_direction_and_stop_unblocks_writes() {
    for (recv_buffer, send_buffer) in [(4 * 1024, 16 * 1024), (16 * 1024, 4 * 1024)] {
        for flow in [Flow::v4(13_500), Flow::v6(13_501)] {
            let mut parts = NetStack::start_tcp(NetStackConfig {
                tcp_recv_buffer: recv_buffer,
                tcp_send_buffer: send_buffer,
                ..NetStackConfig::default()
            })
            .unwrap();
            parts
                .packet_sink
                .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
                .await
                .unwrap();
            let syn_ack = timeout_packet(&mut parts.packet_stream).await;
            assert!(is_syn_ack(&syn_ack, &flow));
            assert_eq!(usize::from(tcp_window(&syn_ack)), recv_buffer / 2);
            let server_sequence = tcp_sequence(&syn_ack).wrapping_add(1);
            let mut stream = parts.tcp_listener.accept().await.unwrap();

            let recv_payload = vec![0x3c; 3000];
            let mut client_sequence = 101_u32;
            for chunk in recv_payload.chunks(1000) {
                parts
                    .packet_sink
                    .send(build_tcp(
                        &flow,
                        client_sequence,
                        server_sequence,
                        TcpFlags::ACK,
                        chunk,
                    ))
                    .await
                    .unwrap();
                client_sequence = client_sequence.wrapping_add(u32::try_from(chunk.len()).unwrap());
                // Wait for each ACK so the driver can transfer received bytes
                // into the application queue before the next ingress batch.
                loop {
                    let reply = timeout_packet(&mut parts.packet_stream).await;
                    if tcp_acknowledgement(&reply) == client_sequence {
                        break;
                    }
                }
            }
            let mut received = vec![0_u8; recv_payload.len()];
            let count = tokio::time::timeout(WAIT, stream.read(&mut received))
                .await
                .expect("asymmetric receive buffer did not deliver data")
                .unwrap();
            assert_eq!(count, recv_payload.len().min(recv_buffer / 2));
            tokio::time::timeout(WAIT, stream.read_exact(&mut received[count..]))
                .await
                .expect("draining the receive queue did not wake the driver")
                .unwrap();
            assert_eq!(received, recv_payload);

            let send_payload = vec![0x5a; send_buffer + 1];
            // This first write completes without yielding to the driver, so
            // it measures the independently sized application send queue.
            let count = stream.write(&send_payload).await.unwrap();
            assert_eq!(count, send_buffer / 2);
            tokio::time::timeout(WAIT, stream.write_all(&send_payload[count..send_buffer]))
                .await
                .expect("TCP send layers did not hold their configured total")
                .unwrap();
            // The peer never ACKs server data: smoltcp retains half the total
            // and the application queue retains the other half.
            let mut blocked = Box::pin(stream.write_all(&send_payload[send_buffer..]));
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut blocked)
                    .await
                    .is_err(),
                "send direction exceeded its configured total"
            );
            parts.control.stop().await;
            assert!(
                tokio::time::timeout(WAIT, blocked)
                    .await
                    .expect("stop did not wake the full asymmetric send queue")
                    .is_err()
            );
            assert!(stream.is_stopped());
            assert_eq!(parts.stats.snapshot().active_tcp, 0);
        }
    }
}

#[tokio::test]
async fn tcp_write_applies_backpressure_and_stop_unblocks_it() {
    let config = NetStackConfig {
        packet_queue: 1,
        tcp_accept_queue: 1,
        udp_queue: 1,
        tcp_recv_buffer: 8 * 1024,
        tcp_send_buffer: 8 * 1024,
        max_poll_interval: Duration::from_millis(5),
        ..NetStackConfig::default()
    };
    let stack = NetStack::start(config).unwrap();
    let mut parts = stack.into_parts();
    let flow = Flow::v4(14_000);
    parts
        .packet_sink
        .send(build_tcp(&flow, 10, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    let syn_ack = timeout_packet(&mut parts.packet_stream).await;
    let server_sequence = tcp_sequence(&syn_ack);
    let mut stream = parts.tcp_listener.accept().await.unwrap();
    parts
        .packet_sink
        .send(build_tcp(
            &flow,
            11,
            server_sequence.wrapping_add(1),
            TcpFlags::ACK,
            &[],
        ))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    let payload = vec![0x5a; 128 * 1024];
    let mut write = Box::pin(stream.write_all(&payload));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut write)
            .await
            .is_err(),
        "write unexpectedly bypassed bounded TCP buffers"
    );

    parts.control.stop().await;
    let write_result = tokio::time::timeout(WAIT, write)
        .await
        .expect("blocked TCP write was not woken by stop");
    assert!(write_result.is_err());
    assert!(stream.is_stopped());
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn rejecting_a_half_open_flow_emits_reset_before_reclaiming_it() {
    for flow in [Flow::v4(14_100), Flow::v6(14_101)] {
        let mut parts = NetStack::start(NetStackConfig {
            packet_queue: 1,
            max_poll_interval: Duration::from_millis(5),
            ..NetStackConfig::default()
        })
        .unwrap()
        .into_parts();
        parts
            .packet_sink
            .send(build_tcp(&flow, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&syn_ack, &flow));
        // The dispatcher can reject immediately, before the client's ACK.
        drop(parts.tcp_listener.accept().await.unwrap());
        let reset = timeout_packet(&mut parts.packet_stream).await;
        let offset = ip_header_len(reset.data());
        assert_ne!(reset.data()[offset + 13] & 0x04, 0, "missing TCP RST");
        assert_eq!(
            u16::from_be_bytes(reset.data()[offset..offset + 2].try_into().unwrap()),
            flow.destination.port()
        );
        tokio::time::timeout(WAIT, async {
            while parts.stats.snapshot().active_tcp != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rejected half-open flow was retained");
        assert_eq!(parts.stats.snapshot().half_open_tcp, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), parts.packet_stream.recv())
                .await
                .is_err(),
            "rejected flow emitted a duplicate reset"
        );
        parts.control.stop().await;
    }
}

#[tokio::test]
async fn half_open_flows_are_not_count_limited_and_udp_queue_remains_bounded() {
    const FLOW_COUNT: usize = 40;

    let config = NetStackConfig {
        packet_queue: 4,
        tcp_accept_queue: 1,
        udp_queue: 1,
        max_poll_interval: Duration::from_millis(5),
        ..NetStackConfig::default()
    };
    let stack = NetStack::start(config).unwrap();
    let mut parts = stack.into_parts();

    let mut half_open_streams = Vec::with_capacity(FLOW_COUNT);
    for index in 0..FLOW_COUNT {
        let flow = Flow::v4(15_000 + u16::try_from(index).unwrap());
        parts
            .packet_sink
            .send(build_tcp(&flow, 1, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout_packet(&mut parts.packet_stream).await;
        assert!(is_syn_ack(&syn_ack, &flow));
        half_open_streams.push(
            tokio::time::timeout(WAIT, parts.tcp_listener.accept())
                .await
                .expect("TCP accept timed out")
                .expect("TCP listener stopped"),
        );
    }

    let tcp_snapshot = parts.stats.snapshot();
    assert_eq!(tcp_snapshot.active_tcp, FLOW_COUNT);
    assert_eq!(tcp_snapshot.active_tcp_peak, FLOW_COUNT);
    assert_eq!(tcp_snapshot.half_open_tcp, FLOW_COUNT);
    assert_eq!(tcp_snapshot.half_open_tcp_peak, FLOW_COUNT);
    assert_eq!(tcp_snapshot.rejected_tcp, 0);

    for port in 16_000..16_003 {
        let flow = Flow::v4(port);
        parts
            .packet_sink
            .send(build_udp(&flow, b"queued"))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(parts.stats.snapshot().dropped_udp >= 2);
    assert!(parts.udp_socket.recv().await.is_some());

    parts.control.stop().await;
    let stopped_snapshot = parts.stats.snapshot();
    assert_eq!(stopped_snapshot.active_tcp, 0);
    assert_eq!(stopped_snapshot.active_tcp_peak, FLOW_COUNT);
    assert_eq!(stopped_snapshot.half_open_tcp, 0);
    assert_eq!(stopped_snapshot.half_open_tcp_peak, FLOW_COUNT);
}

#[tokio::test]
async fn stop_is_a_completion_barrier_for_all_async_endpoints() {
    let stack = NetStack::start(NetStackConfig::default()).unwrap();
    let mut parts = stack.into_parts();
    parts.control.stop().await;

    assert!(parts.control.is_stopped());
    assert!(parts.packet_stream.recv().await.is_none());
    assert!(parts.tcp_listener.accept().await.is_none());
    assert!(parts.udp_socket.recv().await.is_none());
    assert!(matches!(
        parts.packet_sink.send(Packet::new(vec![0x45; 20])).await,
        Err(NetStackError::Stopped)
    ));
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[test]
fn dropping_the_tokio_runtime_still_completes_driver_shutdown() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let parts = runtime.block_on(async {
        NetStack::start(NetStackConfig::default())
            .unwrap()
            .into_parts()
    });
    assert!(!parts.control.is_stopped());

    drop(runtime);

    assert!(parts.control.is_stopped());
    assert_eq!(parts.stats.snapshot().active_tcp, 0);
}

#[tokio::test]
async fn fake_icmp_echo_is_explicitly_gated_and_answers_both_families() {
    let default_stack = NetStack::start(NetStackConfig::default()).unwrap();
    let mut default_parts = default_stack.into_parts();
    default_parts
        .packet_sink
        .send(build_icmpv4_echo(b"default"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            default_parts.packet_stream.recv()
        )
        .await
        .is_err(),
        "default netstack unexpectedly answered ICMP"
    );
    assert_eq!(default_parts.stats.snapshot().icmp_replied, 0);
    default_parts.control.stop().await;

    let stack = NetStack::start(NetStackConfig {
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let mut parts = stack.into_parts();
    for (request, reply_type) in [
        (build_icmpv4_echo(b"odd"), 0_u8),
        (build_icmpv6_echo(b"odd"), 129_u8),
    ] {
        let request_version = request.data()[0] >> 4;
        parts.packet_sink.send(request).await.unwrap();
        let reply = timeout_packet(&mut parts.packet_stream).await;
        assert_eq!(reply.data()[0] >> 4, request_version);
        let offset = ip_header_len(reply.data());
        assert_icmp_checksums(&reply);
        assert_eq!(reply.data()[offset], reply_type);
        assert_eq!(reply.data()[offset + 1], 0);
        assert_eq!(
            &reply.data()[offset + 4..],
            &[0x12, 0x34, 0x56, 0x78, b'o', b'd', b'd']
        );
    }
    let snapshot = parts.stats.snapshot();
    assert_eq!(snapshot.icmp_replied, 2);
    assert_eq!(snapshot.icmp_dropped, 0);
    parts.control.stop().await;
}

#[tokio::test]
async fn fake_icmp_rejects_non_unicast_addresses() {
    let stack = NetStack::start(NetStackConfig {
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let mut parts = stack.into_parts();

    for request in [
        build_icmpv4_echo_between(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(198, 51, 100, 20),
            b"invalid-source",
        ),
        build_icmpv4_echo_between(
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(198, 51, 100, 20),
            b"invalid-source",
        ),
        build_icmpv4_echo_between(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::UNSPECIFIED,
            b"invalid-destination",
        ),
        build_icmpv4_echo_between(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::BROADCAST,
            b"invalid-destination",
        ),
        build_icmpv4_echo_between(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(224, 0, 0, 1),
            b"invalid-destination",
        ),
        build_icmpv6_echo_between(
            Ipv6Addr::UNSPECIFIED,
            "2001:db8:2::20".parse().unwrap(),
            b"invalid-source",
        ),
        build_icmpv6_echo_between(
            "ff02::1".parse().unwrap(),
            "2001:db8:2::20".parse().unwrap(),
            b"invalid-source",
        ),
        build_icmpv6_echo_between(
            "2001:db8:1::10".parse().unwrap(),
            Ipv6Addr::UNSPECIFIED,
            b"invalid-destination",
        ),
        build_icmpv6_echo_between(
            "2001:db8:1::10".parse().unwrap(),
            "ff02::1".parse().unwrap(),
            b"invalid-destination",
        ),
    ] {
        parts.packet_sink.send(request).await.unwrap();
    }

    for _ in 0..50 {
        if parts.stats.snapshot().icmp_dropped == 9 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(parts.stats.snapshot().icmp_dropped, 9);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), parts.packet_stream.recv())
            .await
            .is_err(),
        "fake ICMP replied to a non-unicast address"
    );

    parts.control.stop().await;
}

#[tokio::test]
async fn fake_icmp_preserves_strict_wire_policy_and_mtu() {
    const REJECTED: usize = 9;

    let stack = NetStack::start(NetStackConfig {
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let mut parts = stack.into_parts();

    let mut trailing_v4 = build_icmpv4_echo(b"trailing").data().to_vec();
    trailing_v4.push(0xaa);
    let mut trailing_v6 = build_icmpv6_echo(b"trailing").data().to_vec();
    trailing_v6.push(0xaa);

    let mut bad_ip_checksum = build_icmpv4_echo(b"bad-ip-checksum").data().to_vec();
    bad_ip_checksum[10] ^= 1;
    let mut bad_icmpv4_checksum = build_icmpv4_echo(b"bad-icmp-checksum").data().to_vec();
    bad_icmpv4_checksum[22] ^= 1;
    let mut fragmented = build_icmpv4_echo(b"fragmented").data().to_vec();
    fragmented[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    rewrite_checksum(&mut fragmented[..20], 10);
    let mut non_echo = build_icmpv4_echo(b"non-echo").data().to_vec();
    non_echo[20] = 3;
    rewrite_checksum(&mut non_echo[20..], 2);
    let mut bad_icmpv4_code = build_icmpv4_echo(b"bad-code").data().to_vec();
    bad_icmpv4_code[21] = 1;
    rewrite_checksum(&mut bad_icmpv4_code[20..], 2);

    let mut bad_icmpv6_checksum = build_icmpv6_echo(b"bad-checksum").data().to_vec();
    bad_icmpv6_checksum[42] ^= 1;
    let mut bad_icmpv6_code = build_icmpv6_echo(b"bad-code").data().to_vec();
    bad_icmpv6_code[41] = 1;
    rewrite_icmpv6_checksum(&mut bad_icmpv6_code);

    for bytes in [
        trailing_v4,
        trailing_v6,
        bad_ip_checksum,
        bad_icmpv4_checksum,
        fragmented,
        non_echo,
        bad_icmpv4_code,
        bad_icmpv6_checksum,
        bad_icmpv6_code,
    ] {
        parts.packet_sink.send(Packet::new(bytes)).await.unwrap();
    }

    for _ in 0..100 {
        if parts.stats.snapshot().icmp_dropped == REJECTED {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(parts.stats.snapshot().icmp_dropped, REJECTED);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), parts.packet_stream.recv())
            .await
            .is_err(),
        "invalid ICMP generated a reply"
    );

    let mut extension_header = build_icmpv6_echo(b"extension").data().to_vec();
    extension_header[6] = 44;
    parts
        .packet_sink
        .send(Packet::new(extension_header))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(parts.stats.snapshot().icmp_dropped, REJECTED);

    for (request, expected_len) in [
        (build_icmpv4_echo_with_options(b"odd"), 20 + 8 + 3),
        (build_icmpv4_echo(&vec![0x5a; 1_472]), 1_500),
        (build_icmpv6_echo(&vec![0xa5; 1_452]), 1_500),
    ] {
        parts.packet_sink.send(request).await.unwrap();
        let reply = timeout_packet(&mut parts.packet_stream).await;
        assert_eq!(reply.len(), expected_len);
    }
    assert_eq!(parts.stats.snapshot().icmp_replied, 3);

    parts.control.stop().await;
}

#[tokio::test]
async fn full_raw_egress_drops_only_the_current_icmp_reply() {
    let stack = NetStack::start(NetStackConfig {
        packet_queue: 1,
        fake_icmp_echo: true,
        ..NetStackConfig::default()
    })
    .unwrap();
    let mut parts = stack.into_parts();

    parts
        .packet_sink
        .send(build_icmpv4_echo(b"first"))
        .await
        .unwrap();
    parts
        .packet_sink
        .send(build_icmpv4_echo(b"second"))
        .await
        .unwrap();

    for _ in 0..50 {
        let snapshot = parts.stats.snapshot();
        if snapshot.icmp_replied + snapshot.icmp_dropped == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let snapshot = parts.stats.snapshot();
    assert_eq!(snapshot.icmp_replied, 1);
    assert_eq!(snapshot.icmp_dropped, 1);

    let reply = timeout_packet(&mut parts.packet_stream).await;
    let offset = ip_header_len(reply.data());
    assert_eq!(&reply.data()[offset + 8..], b"first");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), parts.packet_stream.recv())
            .await
            .is_err(),
        "queue-full reply was retained outside the bounded raw egress queue"
    );

    assert!(!parts.control.is_stopped());
    parts.control.stop().await;
    assert!(parts.control.is_stopped());
}

#[derive(Clone, Copy)]
struct Flow {
    source: SocketAddr,
    destination: SocketAddr,
}

impl Flow {
    fn v4(source_port: u16) -> Self {
        Self {
            source: SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), source_port),
            destination: SocketAddr::new(Ipv4Addr::new(198, 51, 100, 20).into(), 443),
        }
    }

    fn v6(source_port: u16) -> Self {
        Self {
            source: SocketAddr::new("2001:db8:1::10".parse().unwrap(), source_port),
            destination: SocketAddr::new("2001:db8:2::20".parse().unwrap(), 443),
        }
    }
}

#[derive(Clone, Copy)]
struct TcpFlags;

impl TcpFlags {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
}

async fn timeout_packet(stream: &mut vole_netstack::PacketStream) -> Packet {
    tokio::time::timeout(WAIT, stream.recv())
        .await
        .expect("raw output timed out")
        .expect("raw output closed")
}

fn build_tcp(flow: &Flow, sequence: u32, ack: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut transport = vec![0_u8; 20 + payload.len()];
    transport[..2].copy_from_slice(&flow.source.port().to_be_bytes());
    transport[2..4].copy_from_slice(&flow.destination.port().to_be_bytes());
    transport[4..8].copy_from_slice(&sequence.to_be_bytes());
    transport[8..12].copy_from_slice(&ack.to_be_bytes());
    transport[12] = 5 << 4;
    transport[13] = flags;
    transport[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    transport[20..].copy_from_slice(payload);

    match (flow.source, flow.destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let checksum = transport_checksum_v4(*source.ip(), *destination.ip(), 6, &transport);
            transport[16..18].copy_from_slice(&checksum.to_be_bytes());
            build_ipv4(*source.ip(), *destination.ip(), 6, &transport)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            let checksum = transport_checksum_v6(*source.ip(), *destination.ip(), 6, &transport);
            transport[16..18].copy_from_slice(&checksum.to_be_bytes());
            build_ipv6(*source.ip(), *destination.ip(), 6, &transport)
        }
        _ => unreachable!(),
    }
}

fn build_udp(flow: &Flow, payload: &[u8]) -> Packet {
    let mut transport = vec![0_u8; 8 + payload.len()];
    let transport_len = u16::try_from(transport.len()).unwrap();
    transport[..2].copy_from_slice(&flow.source.port().to_be_bytes());
    transport[2..4].copy_from_slice(&flow.destination.port().to_be_bytes());
    transport[4..6].copy_from_slice(&transport_len.to_be_bytes());
    transport[8..].copy_from_slice(payload);

    match (flow.source, flow.destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let checksum = transport_checksum_v4(*source.ip(), *destination.ip(), 17, &transport);
            transport[6..8].copy_from_slice(&checksum.to_be_bytes());
            build_ipv4(*source.ip(), *destination.ip(), 17, &transport)
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            let checksum = transport_checksum_v6(*source.ip(), *destination.ip(), 17, &transport);
            transport[6..8].copy_from_slice(&checksum.to_be_bytes());
            build_ipv6(*source.ip(), *destination.ip(), 17, &transport)
        }
        _ => unreachable!(),
    }
}

fn build_icmpv4_echo(payload: &[u8]) -> Packet {
    build_icmpv4_echo_between(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        payload,
    )
}

fn build_icmpv4_echo_between(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Packet {
    let mut message = vec![0_u8; 8 + payload.len()];
    message[0] = 8;
    message[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    message[8..].copy_from_slice(payload);
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    build_ipv4(source, destination, 1, &message)
}

fn build_icmpv4_echo_with_options(payload: &[u8]) -> Packet {
    let base = build_icmpv4_echo(payload);
    let mut packet = vec![0_u8; base.len() + 4];
    let packet_len = u16::try_from(packet.len()).unwrap();
    packet[0] = 0x46;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..20].copy_from_slice(&base.data()[12..20]);
    packet[20..24].copy_from_slice(&[1, 1, 0, 0]);
    packet[24..].copy_from_slice(&base.data()[20..]);
    rewrite_checksum(&mut packet[..24], 10);
    Packet::new(packet)
}

fn build_icmpv6_echo(payload: &[u8]) -> Packet {
    build_icmpv6_echo_between(
        "2001:db8:1::10".parse().unwrap(),
        "2001:db8:2::20".parse().unwrap(),
        payload,
    )
}

fn build_icmpv6_echo_between(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Packet {
    let mut message = vec![0_u8; 8 + payload.len()];
    message[0] = 128;
    message[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    message[8..].copy_from_slice(payload);
    let checksum = transport_checksum_v6(source, destination, 58, &message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    build_ipv6(source, destination, 58, &message)
}

fn build_ipv4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, transport: &[u8]) -> Packet {
    let mut packet = vec![0_u8; 20 + transport.len()];
    packet[0] = 0x45;
    let packet_len = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(transport);
    Packet::new(packet)
}

fn build_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    transport: &[u8],
) -> Packet {
    let mut packet = vec![0_u8; 40 + transport.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(transport.len()).unwrap().to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..].copy_from_slice(transport);
    Packet::new(packet)
}

fn is_syn_ack(packet: &Packet, flow: &Flow) -> bool {
    let offset = ip_header_len(packet.data());
    packet.data().get(offset + 13).copied() == Some(TcpFlags::SYN | TcpFlags::ACK)
        && u16::from_be_bytes(packet.data()[offset..offset + 2].try_into().unwrap())
            == flow.destination.port()
        && u16::from_be_bytes(packet.data()[offset + 2..offset + 4].try_into().unwrap())
            == flow.source.port()
}

fn tcp_sequence(packet: &Packet) -> u32 {
    let offset = ip_header_len(packet.data());
    u32::from_be_bytes(packet.data()[offset + 4..offset + 8].try_into().unwrap())
}

fn tcp_acknowledgement(packet: &Packet) -> u32 {
    let offset = ip_header_len(packet.data());
    u32::from_be_bytes(packet.data()[offset + 8..offset + 12].try_into().unwrap())
}

fn tcp_window(packet: &Packet) -> u16 {
    let offset = ip_header_len(packet.data());
    u16::from_be_bytes(packet.data()[offset + 14..offset + 16].try_into().unwrap())
}

fn assert_icmp_checksums(packet: &Packet) {
    let bytes = packet.data();
    let offset = ip_header_len(bytes);
    match bytes[0] >> 4 {
        4 => {
            assert_eq!(internet_checksum(&bytes[..offset]), u16::MAX);
            assert_eq!(internet_checksum(&bytes[offset..]), u16::MAX);
        }
        6 => {
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap());
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap());
            assert_eq!(
                transport_checksum_v6(source, destination, 58, &bytes[offset..]),
                u16::MAX
            );
        }
        _ => unreachable!(),
    }
}

fn assert_udp_packet(packet: &Packet, expected: &UdpDatagram) {
    let offset = ip_header_len(packet.data());
    assert_eq!(
        u16::from_be_bytes(packet.data()[offset..offset + 2].try_into().unwrap()),
        expected.source.port()
    );
    assert_eq!(
        u16::from_be_bytes(packet.data()[offset + 2..offset + 4].try_into().unwrap()),
        expected.destination.port()
    );
    assert_eq!(&packet.data()[offset + 8..], expected.payload.as_ref());
}

fn ip_header_len(packet: &[u8]) -> usize {
    match packet[0] >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        6 => 40,
        _ => panic!("unexpected IP version"),
    }
}

fn transport_checksum_v4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    transport: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, &source.octets());
    add_bytes(&mut sum, &destination.octets());
    sum += u32::from(protocol);
    sum += u32::try_from(transport.len()).unwrap();
    add_bytes(&mut sum, transport);
    fold(sum)
}

fn transport_checksum_v6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    transport: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, &source.octets());
    add_bytes(&mut sum, &destination.octets());
    let length = u32::try_from(transport.len()).unwrap();
    sum += length >> 16;
    sum += length & 0xffff;
    sum += u32::from(next_header);
    add_bytes(&mut sum, transport);
    fold(sum)
}

fn rewrite_icmpv6_checksum(packet: &mut [u8]) {
    packet[42..44].fill(0);
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let checksum = transport_checksum_v6(source, destination, 58, &packet[40..]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
}

fn rewrite_checksum(bytes: &mut [u8], offset: usize) {
    bytes[offset..offset + 2].fill(0);
    let checksum = internet_checksum(bytes);
    bytes[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, bytes);
    fold(sum)
}

fn add_bytes(sum: &mut u32, bytes: &[u8]) {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        *sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(byte) = remainder.first() {
        *sum += u32::from(*byte) << 8;
    }
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !u16::try_from(sum).expect("folded checksum fits in u16");
    if checksum == 0 { u16::MAX } else { checksum }
}
