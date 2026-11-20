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
            retired: BTreeSet::new(),
            retired_cursor: None,
            retired_debt: 0,
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

// Real QUIC/TLS/H3 packets exercise cancellation collection independently of
// application Body removal, including flow control and shared-owner fairness.
fn halves(wire: &Wire, id: u64) -> (SendStream, RecvStream) {
    let signals = wire.client.shared.state.lock().unwrap().streams[&id]
        .signals
        .clone();
    (
        SendStream {
            client: wire.client.clone(),
            id,
            signals: signals.clone(),
        },
        RecvStream {
            client: wire.client.clone(),
            id,
            signals,
        },
    )
}

fn poll_retirement_peer(peer: &mut NativeConnection, h3: &mut quiche::h3::Connection) {
    for _ in 0..256 {
        match h3.poll(peer) {
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => return,
            Err(error) => panic!("memory retirement peer H3 protocol error: {error:?}"),
        }
    }
    panic!("memory retirement peer H3 work bound exceeded");
}

// Real wire progress without running the candidate reaper, so tests can place
// an already-collected suffix behind an unacknowledged prefix.
fn exchange_without_reaping(wire: &mut Wire, turns: usize) {
    for _ in 0..turns {
        let mut state = wire.client.shared.state.lock().unwrap();
        state
            .connection
            .as_mut()
            .unwrap()
            .send_ack_eliciting()
            .unwrap();
        transfer(
            state.connection.as_mut().unwrap(),
            &mut wire.peer,
            wire.local,
            wire.remote,
        );
        poll_retirement_peer(&mut wire.peer, &mut wire.peer_h3);
        wire.peer.send_ack_eliciting().unwrap();
        if transfer(
            &mut wire.peer,
            state.connection.as_mut().unwrap(),
            wire.remote,
            wire.local,
        ) != 0
        {
            // Mirrors the owner hook only after actual native recv succeeded.
            state.retired_debt = state.retired.len();
        }
        super::process_h3(&mut state, &mut { WORK }).unwrap();
    }
}

fn admit_retirement_requests(wire: &mut Wire, count: usize) -> Vec<u64> {
    let mut ids = wire.ids.to_vec();
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        for _ in 0..count {
            let request = Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.invalid/")
                .body(())
                .unwrap();
            let headers = request_headers(&request).unwrap();
            let State {
                connection,
                h3,
                streams,
                ..
            } = &mut *state;
            let id = h3
                .as_mut()
                .unwrap()
                .send_request(connection.as_mut().unwrap(), &headers, false)
                .unwrap();
            streams.insert(id, Body::new(Arc::new(Signals::default())));
            ids.push(id);
        }
    }
    for _ in 0..8 {
        let mut state = wire.client.shared.state.lock().unwrap();
        transfer(
            state.connection.as_mut().unwrap(),
            &mut wire.peer,
            wire.local,
            wire.remote,
        );
        let mut drained = false;
        for _ in 0..256 {
            match wire.peer_h3.poll(&mut wire.peer) {
                Ok((id, quiche::h3::Event::Headers { .. })) => {
                    wire.peer_h3
                        .send_response(
                            &mut wire.peer,
                            id,
                            &[quiche::h3::Header::new(b":status", b"200")],
                            false,
                        )
                        .unwrap();
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => {
                    drained = true;
                    break;
                }
                Err(error) => panic!("memory retirement admission H3 error: {error:?}"),
            }
        }
        assert!(
            drained,
            "memory retirement admission H3 work bound exceeded"
        );
        transfer(
            &mut wire.peer,
            state.connection.as_mut().unwrap(),
            wire.remote,
            wire.local,
        );
        super::process_h3(&mut state, &mut { WORK }).unwrap();
    }
    for id in &ids {
        assert_eq!(
            wire.client.shared.state.lock().unwrap().streams[id]
                .headers
                .as_ref()
                .unwrap()
                .status(),
            200
        );
    }
    ids
}

fn exchange_reset_wire(wire: &mut Wire, id: u64) {
    for _ in 0..128 {
        let mut state = wire.client.shared.state.lock().unwrap();
        // Synthetic PINGs make ACK progress observable without sleeps, an OS
        // socket, a new task, or fabricated acknowledgement state.
        state
            .connection
            .as_mut()
            .unwrap()
            .send_ack_eliciting()
            .unwrap();
        transfer(
            state.connection.as_mut().unwrap(),
            &mut wire.peer,
            wire.local,
            wire.remote,
        );
        poll_retirement_peer(&mut wire.peer, &mut wire.peer_h3);
        wire.peer.send_ack_eliciting().unwrap();
        if transfer(
            &mut wire.peer,
            state.connection.as_mut().unwrap(),
            wire.remote,
            wire.local,
        ) != 0
        {
            state.retired_debt = state.retired.len();
        }
        super::process_h3(&mut state, &mut { WORK }).unwrap();
        super::reap_retired_h3(&mut state, &mut { WORK });
        let native = state.connection.as_mut().unwrap();
        if native.stream_closed(id)
            && matches!(
                native.stream_capacity(id),
                Err(quiche::Error::InvalidStreamState(_))
            )
        {
            return;
        }
    }
    panic!("native reset was not collected within bounded real wire exchanges");
}

fn assert_h3_forgotten_without_wire_output(wire: &Wire, id: u64) {
    let mut state = wire.client.shared.state.lock().unwrap();
    let State { connection, h3, .. } = &mut *state;
    let native = connection.as_mut().unwrap();
    assert!(native.stream_closed(id));
    assert!(matches!(
        native.stream_capacity(id),
        Err(quiche::Error::InvalidStreamState(_))
    ));
    let sent = native.stats().sent;
    // The native absent/collected gate is the no-output proof. Packet count
    // below is auxiliary, not proof that an arbitrary API queued no FIN.
    // This is a mutable public API probe, not a getter. An empty non-FIN body
    // is deliberately rejected before native output. Done means a stale H3
    // entry survived; FrameUnexpected means the request entry is absent.
    assert!(matches!(
        h3.as_mut().unwrap().send_body(native, id, &[], false),
        Err(quiche::h3::Error::FrameUnexpected)
    ));
    assert_eq!(native.stats().sent, sent);
}

#[test]
fn quiche_h3_native_memory_dropped_halves_retire_h3_after_actual_native_collection() {
    for read_first in [false, true] {
        let mut wire = Wire::new();
        let id = wire.ids[0];
        let (mut send, receive) = halves(&wire, id);
        if read_first {
            drop(receive);
            // The surviving upload and its Body stay owned until its Drop.
            assert!(
                wire.client
                    .shared
                    .state
                    .lock()
                    .unwrap()
                    .streams
                    .contains_key(&id)
            );
            send.stop_stream(REQUEST_CANCELLED);
            send.stop_stream(REQUEST_CANCELLED); // Explicit stop + Drop is idempotent.
            drop(send);
        } else {
            drop(send);
            assert!(
                wire.client
                    .shared
                    .state
                    .lock()
                    .unwrap()
                    .streams
                    .contains_key(&id)
            );
            drop(receive);
        }
        assert!(
            !wire
                .client
                .shared
                .state
                .lock()
                .unwrap()
                .streams
                .contains_key(&id)
        );
        exchange_reset_wire(&mut wire, id);
        // One extra owner turn covers collection caused by the final native
        // capacity check, without advancing a timer or resetting the carrier.
        super::reap_retired_h3(&mut wire.client.shared.state.lock().unwrap(), &mut { WORK });
        assert_h3_forgotten_without_wire_output(&wire, id);
        assert!(wire.client.shared.state.lock().unwrap().retired.is_empty());

        let sibling = wire.ids[1];
        wire.peer_h3
            .send_body(&mut wire.peer, sibling, b"sibling", false)
            .unwrap();
        wire.receive_wire();
        wire.publish(&mut { WORK });
        let (_sibling_send, mut sibling_receive) = halves(&wire, sibling);
        assert_eq!(
            sibling_receive
                .recv_response()
                .now_or_never()
                .unwrap()
                .unwrap()
                .status(),
            200
        );
        let data = futures_util::future::poll_fn(|cx| sibling_receive.poll_recv_data(cx))
            .now_or_never()
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(data.as_ref(), b"sibling");
        assert!(wire.client.can_open_request());
    }
}

#[test]
fn quiche_h3_native_memory_retirement_waits_without_fin_under_actual_backpressure() {
    let mut wire = Wire::new();
    let id = wire.ids[0];
    let (send, receive) = halves(&wire, id);
    // Fill the real native/H3 sender until it rejects new data. No model or
    // forced credit variable stands in for transport backpressure.
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        let State { connection, h3, .. } = &mut *state;
        let mut blocked = false;
        for _ in 0..256 {
            match h3.as_mut().unwrap().send_body(
                connection.as_mut().unwrap(),
                id,
                &[0x61; CHUNK],
                false,
            ) {
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("unexpected memory backpressure result: {error:?}"),
            }
        }
        assert!(blocked);
    }
    drop(send);
    drop(receive);
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        let native = state.connection.as_mut().unwrap();
        let sent = native.stats().sent;
        assert!(!super::retire_collected_h3(&mut state, id));
        let mut budget = 1;
        assert!(!super::reap_retired_h3(&mut state, &mut budget));
        assert_eq!(budget, 0);
        assert!(state.retired.contains(&id));
        assert_eq!(state.connection.as_ref().unwrap().stats().sent, sent);
        assert!(!state.streams.contains_key(&id));
    }
    exchange_reset_wire(&mut wire, id);
    super::reap_retired_h3(&mut wire.client.shared.state.lock().unwrap(), &mut { WORK });
    assert_h3_forgotten_without_wire_output(&wire, id);
    // The same final owner teardown used by Driver::run drops all native/H3
    // state and tombstones. Full driver stop/join remains covered separately.
    wire.client.shared.finish();
    let state = wire.client.shared.state.lock().unwrap();
    assert!(state.streams.is_empty() && state.retired.is_empty());
    assert!(state.h3.is_none() && state.connection.is_none());
}

#[test]
fn quiche_h3_native_memory_pending_retirement_round_robin_uses_only_shared_allowance() {
    let wire = Wire::new();
    for id in wire.ids {
        let (send, receive) = halves(&wire, id);
        drop(send);
        drop(receive);
    }
    let mut state = wire.client.shared.state.lock().unwrap();
    assert_eq!(state.retired.len(), 2);
    let mut allowance = 1;
    assert!(super::reap_retired_h3(&mut state, &mut allowance));
    assert_eq!(allowance, 0);
    let first = state.retired_cursor;
    // The second pass in the SAME owner turn has zero remaining work.
    assert!(super::reap_retired_h3(&mut state, &mut allowance));
    assert_eq!(state.retired_cursor, first);
    allowance = 1;
    assert!(!super::reap_retired_h3(&mut state, &mut allowance));
    assert_eq!(allowance, 0);
    assert_ne!(state.retired_cursor, first);
    assert_eq!(state.retired.len(), 2);
    assert!(state.streams.is_empty());
    drop(state);
    wire.client.shared.finish();
    assert!(wire.client.shared.state.lock().unwrap().retired.is_empty());
}

#[test]
fn quiche_h3_native_memory_graceful_fin_does_not_add_reset_or_retirement() {
    let mut wire = Wire::new();
    let id = wire.ids[0];
    let (mut send, mut receive) = halves(&wire, id);
    send.finish().now_or_never().unwrap().unwrap();
    wire.peer_h3
        .send_body(&mut wire.peer, id, &[], true)
        .unwrap();
    for _ in 0..4 {
        let mut state = wire.client.shared.state.lock().unwrap();
        transfer(
            state.connection.as_mut().unwrap(),
            &mut wire.peer,
            wire.local,
            wire.remote,
        );
        poll_retirement_peer(&mut wire.peer, &mut wire.peer_h3);
        transfer(
            &mut wire.peer,
            state.connection.as_mut().unwrap(),
            wire.remote,
            wire.local,
        );
        super::process_h3(&mut state, &mut { WORK }).unwrap();
    }
    assert_eq!(
        receive
            .recv_response()
            .now_or_never()
            .unwrap()
            .unwrap()
            .status(),
        200
    );
    assert!(
        futures_util::future::poll_fn(|cx| receive.poll_recv_data(cx))
            .now_or_never()
            .unwrap()
            .unwrap()
            .is_none()
    );
    let before = wire
        .client
        .shared
        .state
        .lock()
        .unwrap()
        .connection
        .as_ref()
        .unwrap()
        .stats();
    drop(receive);
    drop(send);
    let state = wire.client.shared.state.lock().unwrap();
    let after = state.connection.as_ref().unwrap().stats();
    assert_eq!(
        after.reset_stream_count_local,
        before.reset_stream_count_local
    );
    assert_eq!(
        after.stopped_stream_count_local,
        before.stopped_stream_count_local
    );
    assert!(state.retired.is_empty());
    assert!(!state.streams.contains_key(&id));
}

#[test]
fn quiche_h3_native_memory_peer_stop_sending_collection_is_rechecked_in_same_drop() {
    let mut wire = Wire::new();
    // Consume response FIN BEFORE the upload is stopped. Reading FIN after
    // RESET/ACK could collect native state in stream_recv and miss the exact
    // capacity-query branch this regression must exercise.
    for id in wire.ids {
        wire.peer_h3
            .send_body(&mut wire.peer, id, &[], true)
            .unwrap();
    }
    for _ in 0..4 {
        let mut state = wire.client.shared.state.lock().unwrap();
        transfer(
            &mut wire.peer,
            state.connection.as_mut().unwrap(),
            wire.remote,
            wire.local,
        );
        super::process_h3(&mut state, &mut { WORK }).unwrap();
    }
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        for id in wire.ids {
            assert!(
                state.streams[&id].finished,
                "response FIN not consumed before STOP for {id}"
            );
            let native = state.connection.as_mut().unwrap();
            // Actual public writable-interest registration, above this real
            // stream's 128 KiB credit; no private flag or fabricated state.
            // STOP sees was_writable=false and links the writable notification
            // which ACK collection preserves until StreamStopped is consumed.
            let writable = native.stream_writable(id, 1024 * 1024);
            assert!(
                matches!(writable, Ok(false)),
                "expected blocked writable interest for {id}: {writable:?}"
            );
        }
    }
    // Now encode STOP_SENDING separately, then exchange genuine RESET/ACKs.
    // No later FIN read is allowed to consume the collection opportunity.
    for id in wire.ids {
        wire.peer
            .stream_shutdown(id, quiche::Shutdown::Read, REQUEST_CANCELLED)
            .unwrap();
    }
    exchange_without_reaping(&mut wire, 64);
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        let native = state.connection.as_mut().unwrap();
        let control = wire.ids[0];
        assert!(native.stream_closed(control));
        // This real stopped stream demonstrates the API's one-call-late
        // return: the first query collects but still reports StreamStopped.
        let first = native.stream_capacity(control);
        assert!(
            matches!(first, Err(quiche::Error::StreamStopped(_))),
            "first stopped capacity query must collect and report StreamStopped: {first:?}"
        );
        let second = native.stream_capacity(control);
        assert!(
            matches!(second, Err(quiche::Error::InvalidStreamState(_))),
            "second capacity query must see native collection: {second:?}"
        );
    }
    let id = wire.ids[1];
    let (send, receive) = halves(&wire, id);
    drop(receive);
    drop(send);
    // No new packet, timer, reaper turn or caller-side capacity query occurs
    // between the last Drop and this assertion.
    assert_h3_forgotten_without_wire_output(&wire, id);
    assert!(
        !wire
            .client
            .shared
            .state
            .lock()
            .unwrap()
            .retired
            .contains(&id)
    );
}

#[test]
fn quiche_h3_native_memory_finite_sweep_reaches_ready_tail_after_unacked_prefix() {
    let mut wire = Wire::new();
    let ids = admit_retirement_requests(&mut wire, WORK);
    assert_eq!(ids.len(), WORK + 2);
    let (waiting, ready) = ids.split_at(WORK);
    // Retire the high-ID suffix and let its genuine RESET/ACK exchange finish.
    // The candidate reaper is deliberately not run during this wire flush.
    for &id in ready {
        let (send, receive) = halves(&wire, id);
        drop(send);
        drop(receive);
    }
    exchange_without_reaping(&mut wire, 64);
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        for &id in ready {
            let native = state.connection.as_mut().unwrap();
            assert!(native.stream_closed(id));
            if matches!(
                native.stream_capacity(id),
                Err(quiche::Error::StreamStopped(_))
            ) {
                assert!(matches!(
                    native.stream_capacity(id),
                    Err(quiche::Error::InvalidStreamState(_))
                ));
            }
            assert!(matches!(
                native.stream_capacity(id),
                Err(quiche::Error::InvalidStreamState(_))
            ));
            assert!(state.retired.contains(&id));
        }
    }
    // Now retire the lower IDs without delivering their STOP/RESET to the
    // peer. No later RX event is available to rescue an incorrectly stopped
    // first batch. Every ID was a real admitted request, not a fake tombstone.
    for &id in waiting {
        let (send, receive) = halves(&wire, id);
        drop(send);
        drop(receive);
    }
    {
        let mut state = wire.client.shared.state.lock().unwrap();
        assert_eq!(state.retired.len(), ids.len());
        assert_eq!(state.retired_debt, ids.len());
        assert!(state.streams.is_empty());
        let mut allowance = WORK;
        assert!(super::reap_retired_h3(&mut state, &mut allowance));
        assert_eq!(allowance, 0);
        assert_eq!(state.retired_debt, 2);
        assert!(ready.iter().all(|id| state.retired.contains(id)));
        allowance = WORK;
        assert!(!super::reap_retired_h3(&mut state, &mut allowance));
        assert_eq!(allowance, WORK - 2);
        assert_eq!(state.retired_debt, 0);
        assert_eq!(state.retired.len(), waiting.len());
        assert!(ready.iter().all(|id| !state.retired.contains(id)));
        let cursor = state.retired_cursor;
        // A peer which never ACKs cannot cause an unbounded cleanup self-loop.
        for _ in 0..4 {
            allowance = WORK;
            assert!(!super::reap_retired_h3(&mut state, &mut allowance));
            assert_eq!(allowance, WORK);
            assert_eq!(state.retired_cursor, cursor);
            assert_eq!(state.retired_debt, 0);
        }
    }
    for &id in ready {
        assert_h3_forgotten_without_wire_output(&wire, id);
    }
    wire.client.shared.finish();
    let state = wire.client.shared.state.lock().unwrap();
    assert!(state.retired.is_empty());
    assert_eq!(state.retired_debt, 0);
}
