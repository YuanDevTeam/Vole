//! UNCOMPILED / UNRUN review draft. Memory-only real quiche wire exchange.
//! No listeners, background tasks, timers, production probes, or new limits.
use super::*;
use futures_util::FutureExt;

struct Wire {
    client: Client,
    peer: NativeConnection,
    peer_h3: quiche::h3::Connection,
    ids: [u64; 2],
    local: SocketAddr,
    remote: SocketAddr,
}

// Quiche's actual packet encoder/decoder; this fixture does not model pacing.
fn transfer(
    from: &mut NativeConnection,
    to: &mut NativeConnection,
    source: SocketAddr,
    destination: SocketAddr,
) -> usize {
    let mut packet = [0; 1400];
    let mut count = 0;
    for _ in 0..128 {
        match from.send(&mut packet) {
            Ok((n, _)) => {
                to.recv(
                    &mut packet[..n],
                    quiche::RecvInfo {
                        from: source,
                        to: destination,
                    },
                )
                .unwrap();
                count += 1;
            }
            Err(quiche::Error::Done) => return count,
            Err(error) => panic!("memory quiche send: {error:?}"),
        }
    }
    panic!("memory packet-transfer bound exceeded");
}

impl Wire {
    fn new() -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let config = || {
            let mut builder =
                boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
            builder
                .set_certificate(&boring::x509::X509::from_der(identity.cert.der()).unwrap())
                .unwrap();
            builder
                .set_private_key(
                    &boring::pkey::PKey::private_key_from_der(
                        &identity.signing_key.serialize_der(),
                    )
                    .unwrap(),
                )
                .unwrap();
            let mut config =
                quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
                    .unwrap();
            config.set_application_protos(&[b"h3"]).unwrap();
            config.verify_peer(false); // Only this generated in-memory identity.
            config.set_max_idle_timeout(10_000);
            config.set_max_recv_udp_payload_size(1400);
            config.set_max_send_udp_payload_size(1400);
            config.set_initial_max_data(1024 * 1024);
            config.set_initial_max_stream_data_bidi_local(128 * 1024);
            config.set_initial_max_stream_data_bidi_remote(128 * 1024);
            config.set_initial_max_stream_data_uni(16 * 1024);
            config.set_initial_max_streams_bidi(256);
            config.set_initial_max_streams_uni(8);
            config.enable_dgram(true, DATAGRAM_QUEUE, DATAGRAM_QUEUE);
            config
        };
        let local: SocketAddr = "192.0.2.2:44301".parse().unwrap();
        let remote: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let cid = [1; 20];
        let mut client = quiche::connect_with_buffer_factory::<OwnedBuffers>(
            Some("localhost"),
            &quiche::ConnectionId::from_ref(&cid),
            local,
            remote,
            &mut config(),
        )
        .unwrap();
        let mut first = [0; 1400];
        let (n, _) = client.send(&mut first).unwrap();
        let header = quiche::Header::from_slice(&mut first[..n], 20).unwrap();
        let dcid = header.dcid.into_owned();
        let mut peer = quiche::accept_with_buf_factory::<OwnedBuffers>(
            &dcid,
            None,
            remote,
            local,
            &mut config(),
        )
        .unwrap();
        peer.recv(
            &mut first[..n],
            quiche::RecvInfo {
                from: local,
                to: remote,
            },
        )
        .unwrap();
        for _ in 0..128 {
            transfer(&mut peer, &mut client, remote, local);
            transfer(&mut client, &mut peer, local, remote);
            if client.is_established() && peer.is_established() {
                break;
            }
        }
        assert!(client.is_established() && peer.is_established());
        let mut h3_config = quiche::h3::Config::new().unwrap();
        h3_config.enable_extended_connect(true);
        let h3 = quiche::h3::Connection::with_transport(&mut client, &h3_config).unwrap();
        let mut peer_h3 = quiche::h3::Connection::with_transport(&mut peer, &h3_config).unwrap();
        let mut state = State {
            connection: Some(client),
            h3: Some(h3),
            streams: BTreeMap::new(),
            closed: false,
            goaway: false,
            ready: true,
            datagram_budget: None,
            settings: None,
        };
        // SETTINGS must be actually received before extended CONNECT admission.
        for _ in 0..4 {
            transfer(state.connection.as_mut().unwrap(), &mut peer, local, remote);
            loop {
                match peer_h3.poll(&mut peer) {
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(error) => panic!("memory H3 settings: {error:?}"),
                }
            }
            transfer(&mut peer, state.connection.as_mut().unwrap(), remote, local);
            publish(&mut state, &mut { WORK });
        }
        let mut ids = [0; 2];
        for id in &mut ids {
            let mut request = Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.invalid/")
                .body(())
                .unwrap();
            request.extensions_mut().insert(Protocol::CF_CONNECT_IP);
            let headers = request_headers(&request).unwrap();
            *id = state
                .h3
                .as_mut()
                .unwrap()
                .send_request(state.connection.as_mut().unwrap(), &headers, false)
                .unwrap();
            let mut body = Body::new(Arc::new(Signals::default()));
            body.datagrams = Some(VecDeque::new());
            state.streams.insert(*id, body);
        }
        for _ in 0..4 {
            transfer(state.connection.as_mut().unwrap(), &mut peer, local, remote);
            while let Ok((id, event)) = peer_h3.poll(&mut peer) {
                if let quiche::h3::Event::Headers { .. } = event {
                    peer_h3
                        .send_response(
                            &mut peer,
                            id,
                            &[quiche::h3::Header::new(b":status", b"200")],
                            false,
                        )
                        .unwrap();
                }
            }
            transfer(&mut peer, state.connection.as_mut().unwrap(), remote, local);
            publish(&mut state, &mut { WORK });
        }
        for id in ids {
            assert_eq!(state.streams[&id].headers.as_ref().unwrap().status(), 200);
        }
        Self {
            client: Client {
                shared: Arc::new(Shared {
                    state: Mutex::new(state),
                    changed: Notify::new(),
                    status: Notify::new(),
                }),
            },
            peer,
            peer_h3,
            ids,
            local,
            remote,
        }
    }
    fn enqueue(&mut self, id: u64, marker: u8) {
        assert!(id / 4 < 64);
        self.peer
            .dgram_send_buf(Bytes::from(vec![(id / 4) as u8, 0, marker]))
            .unwrap();
    }
    fn receive_wire(&mut self) {
        let mut state = self.client.shared.state.lock().unwrap();
        assert!(
            transfer(
                &mut self.peer,
                state.connection.as_mut().unwrap(),
                self.remote,
                self.local
            ) != 0
        );
    }
    fn publish(&self, remaining: &mut usize) {
        publish(&mut self.client.shared.state.lock().unwrap(), remaining);
    }
}

// Candidate adapter: the real two production functions, not a copied algorithm.
// Baseline adapter is supplied separately. Select ONLY the two terminal tests
// against baseline; its owner does not have the candidate's shared allowance.
fn publish(state: &mut State, remaining: &mut usize) {
    super::drain_datagrams(state, remaining).unwrap();
    super::process_h3(state, remaining).unwrap();
}

#[test]
fn quiche_h3_native_memory_wire_shared_32_allowance() {
    let mut wire = Wire::new();
    for marker in 0..64 {
        wire.enqueue(wire.ids[0], marker);
    }
    wire.receive_wire();
    let mut remaining = WORK;
    wire.publish(&mut remaining);
    assert_eq!(remaining, 0);
    for _ in 0..2 {
        wire.publish(&mut remaining);
    }
    {
        let state = wire.client.shared.state.lock().unwrap();
        assert_eq!(
            state.connection.as_ref().unwrap().dgram_recv_queue_len(),
            32
        );
        assert_eq!(
            state.streams[&wire.ids[0]]
                .datagrams
                .as_ref()
                .unwrap()
                .len(),
            32
        );
    }
    wire.publish(&mut { WORK });
    for marker in 0..64 {
        let frame = wire
            .client
            .read_datagram(wire.ids[0])
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(frame.as_ref(), &[(wire.ids[0] / 4) as u8, 0, marker]);
    }
    assert!(
        wire.client
            .read_datagram(wire.ids[0])
            .now_or_never()
            .is_none()
    );
}

#[test]
fn quiche_h3_native_memory_invalid_unknown_full_consume_allowance() {
    let mut wire = Wire::new();
    for marker in 0..64 {
        wire.enqueue(wire.ids[0], marker);
    }
    wire.receive_wire();
    wire.publish(&mut { WORK });
    wire.publish(&mut { WORK });
    // All three drop paths count; no input may admit a new map entry.
    for marker in 0..33 {
        let frame = match marker % 3 {
            0 => vec![0xc0],                               // Incomplete 8-byte varint.
            1 => vec![63, 0, marker],                      // Unknown request flow ID.
            _ => vec![(wire.ids[0] / 4) as u8, 0, marker], // Existing full Body.
        };
        wire.peer.dgram_send_buf(Bytes::from(frame)).unwrap();
    }
    wire.receive_wire();
    let mut remaining = WORK;
    wire.publish(&mut remaining);
    let state = wire.client.shared.state.lock().unwrap();
    assert_eq!(remaining, 0);
    assert_eq!(state.streams.len(), 2);
    assert_eq!(state.connection.as_ref().unwrap().dgram_recv_queue_len(), 1);
    assert_eq!(
        state.streams[&wire.ids[0]]
            .datagrams
            .as_ref()
            .unwrap()
            .len(),
        DATAGRAM_QUEUE
    );
}

#[test]
fn quiche_h3_native_memory_actual_terminal_closes_only_its_registered_flow() {
    // After quiche actually reports empty FIN or RESET, existing read_datagram
    // semantics reject that flow. No cross-stream DATAGRAM/FIN wire order claim.
    for reset in [false, true] {
        let mut wire = Wire::new();
        wire.enqueue(wire.ids[0], 0x41);
        wire.enqueue(wire.ids[1], 0x42);
        if reset {
            wire.peer
                .stream_shutdown(wire.ids[0], quiche::Shutdown::Write, REQUEST_CANCELLED)
                .unwrap();
        } else {
            wire.peer_h3
                .send_body(&mut wire.peer, wire.ids[0], b"", true)
                .unwrap();
        }
        wire.receive_wire();
        wire.publish(&mut { WORK });
        {
            let state = wire.client.shared.state.lock().unwrap();
            let body = &state.streams[&wire.ids[0]];
            assert!(if reset { body.failed } else { body.finished });
            assert!(!state.streams[&wire.ids[1]].failed);
        }
        assert!(
            wire.client
                .read_datagram(wire.ids[0])
                .now_or_never()
                .unwrap()
                .is_err()
        );
        let sibling = wire
            .client
            .read_datagram(wire.ids[1])
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(sibling.as_ref(), &[(wire.ids[1] / 4) as u8, 0, 0x42]);
    }
}

#[test]
fn quiche_h3_native_memory_data_fin_preserves_delivered_prefix_until_finished_poll() {
    let mut wire = Wire::new();
    wire.enqueue(wire.ids[0], 0x41);
    wire.enqueue(wire.ids[0], 0x42);
    wire.peer_h3
        .send_body(&mut wire.peer, wire.ids[0], b"capsule", true)
        .unwrap();
    wire.receive_wire();
    wire.publish(&mut { WORK });
    {
        let state = wire.client.shared.state.lock().unwrap();
        // Quiche records Finished while recv_body consumes the final DATA.
        // It is delivered by the NEXT h3.poll, not retroactively in this pass.
        assert!(!state.streams[&wire.ids[0]].finished);
        assert_eq!(state.streams[&wire.ids[0]].buffered, b"capsule".len());
    }
    let prefix = wire
        .client
        .read_datagram(wire.ids[0])
        .now_or_never()
        .unwrap()
        .unwrap();
    assert_eq!(prefix.as_ref(), &[(wire.ids[0] / 4) as u8, 0, 0x41]);
    wire.publish(&mut { WORK });
    assert!(wire.client.shared.state.lock().unwrap().streams[&wire.ids[0]].finished);
    assert!(
        wire.client
            .read_datagram(wire.ids[0])
            .now_or_never()
            .unwrap()
            .is_err()
    );
}
