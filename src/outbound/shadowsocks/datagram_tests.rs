use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use shadowsocks::{config::ServerType, context::Context, crypto::CipherKind};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Semaphore, mpsc};

const CIPHERS: [&str; 3] = [
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

struct MockTransport {
    sent: mpsc::Sender<Datagram>,
    replies: mpsc::Receiver<Datagram>,
    permits: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
}

#[async_trait]
impl DatagramTransport for MockTransport {
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        self.permits.acquire().await.unwrap().forget();
        self.sent.send(packet).await.unwrap();
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.replies
            .recv()
            .await
            .ok_or(DispatchError::HostUnreachable)
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct Fixture {
    client: SsDatagram,
    server: ProxySocket<PacketIo>,
    io: PacketIo,
    sent: mpsc::Receiver<Datagram>,
    replies: mpsc::Sender<Datagram>,
    permits: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
}

impl Fixture {
    fn new(name: &str, maximum: u16) -> Self {
        let method: CipherKind = name.parse().unwrap();
        let config = ServerConfig::new(
            ("127.0.0.1", 12345),
            STANDARD.encode(vec![7; method.key_len()]),
            method,
        )
        .unwrap();
        let (tx, sent) = mpsc::channel(32);
        let (replies, rx) = mpsc::channel(32);
        let permits = Arc::new(Semaphore::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let inner = MockTransport {
            sent: tx,
            replies: rx,
            permits: permits.clone(),
            closed: closed.clone(),
        };
        let client = SsDatagram::new(
            Box::new(inner),
            Destination::Ip("127.0.0.1:12345".parse().unwrap()),
            Context::new_shared(ServerType::Local),
            &config,
            maximum,
            maximum.saturating_add(MAX_RESPONSE_HEADER),
        );
        let io = PacketIo::default();
        let server = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &config,
            io.clone(),
        );
        Self {
            client,
            server,
            io,
            sent,
            replies,
            permits,
            closed,
        }
    }

    async fn response(&self, control: &UdpSocketControlData, payload: &[u8]) -> Datagram {
        self.server
            .send_with_ctrl(&super::super::address(&target()), control, payload)
            .await
            .unwrap();
        Datagram {
            remote: self.client.server.clone(),
            payload: self.io.take().unwrap(),
            sniffed_domain: None,
        }
    }

    fn control(&self, server_session_id: u64, packet_id: u64) -> UdpSocketControlData {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client.control.client_session_id;
        control.server_session_id = server_session_id;
        control.packet_id = packet_id;
        control
    }

    async fn decode_request(&self, wire: Datagram) -> (Vec<u8>, UdpSocketControlData) {
        assert_eq!(wire.remote, self.client.server);
        self.io.put(wire.payload).unwrap();
        let mut buffer = vec![0; MAX_WIRE_PACKET];
        let (size, actual, _, control) = self.server.recv_with_ctrl(&mut buffer).await.unwrap();
        assert_eq!(actual, super::super::address(&target()));
        (buffer[..size].to_vec(), control.unwrap())
    }
}

fn target() -> Destination {
    Destination::domain("fixture.invalid", 53).unwrap()
}
fn request(payload: &'static [u8]) -> Datagram {
    Datagram {
        remote: target(),
        payload: Bytes::from_static(payload),
        sniffed_domain: None,
    }
}

#[tokio::test]
async fn udp_busy_sender_yields_before_accepting_another_wire_packet() {
    for name in CIPHERS {
        let mut f = Fixture::new(name, 1500);
        f.permits.add_permits(2 * SEND_BURST + 1);
        for _ in 0..SEND_BURST {
            f.client.send(request(b"burst")).await.unwrap();
        }
        // With writable IO, a new send must give other ready tasks a turn
        // before adding another packet to the physical peer's burst.
        let mut sending = Box::pin(f.client.send(request(b"after-burst")));
        assert!(futures_util::poll!(&mut sending).is_pending());
        assert_eq!(f.sent.len(), SEND_BURST);
        drop(sending);
        // Cancellation at that scheduling boundary has not encoded or sent
        // the new packet, and must not poison its nonce/control ownership.
        f.client.send(request(b"resumed")).await.unwrap();
        assert_eq!(f.sent.len(), SEND_BURST + 1);
        assert_eq!(f.client.control.packet_id, SEND_BURST as u64 + 1);
        let progressed = Arc::new(AtomicBool::new(false));
        let sibling = {
            let progressed = progressed.clone();
            tokio::spawn(async move { progressed.store(true, Ordering::SeqCst) })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            for _ in 0..SEND_BURST {
                f.client.send(request(b"more")).await.unwrap();
            }
        })
        .await
        .expect("writable packets must continue after yielding");
        assert!(
            progressed.load(Ordering::SeqCst),
            "busy sending starved a ready sibling"
        );
        sibling.await.unwrap();
        assert_eq!(f.sent.len(), 2 * SEND_BURST + 1);
        f.client.close().await.unwrap();
    }
}

#[tokio::test]
async fn udp_one_session_preserves_multiple_ip_targets_across_receive_cancellation() {
    for name in CIPHERS {
        let mut f = Fixture::new(name, 1500);
        let shareable = f.client.supports_shared_destinations();
        let id = f.client.control.client_session_id;
        for (index, address) in ["192.0.2.1:53", "[2001:db8::1]:443", "192.0.2.1:54"]
            .into_iter()
            .enumerate()
        {
            assert!(futures_util::poll!(f.client.receive()).is_pending());
            let target = Destination::Ip(address.parse().unwrap());
            let packet = Datagram {
                remote: target.clone(),
                payload: Bytes::from_static(b"multi-target"),
                sniffed_domain: None,
            };
            f.permits.add_permits(1);
            f.client.send(packet.clone()).await.unwrap();
            f.io.put(f.sent.recv().await.unwrap().payload).unwrap();
            let mut buffer = [0; 2048];
            let (size, actual, _, control) = f.server.recv_with_ctrl(&mut buffer).await.unwrap();
            assert_eq!(actual, super::super::address(&target));
            assert_eq!(&buffer[..size], packet.payload);
            assert_eq!(control.unwrap().client_session_id, id);
            f.server
                .send_with_ctrl(&actual, &f.control(7, index as u64 + 1), &buffer[..size])
                .await
                .unwrap();
            f.replies
                .send(Datagram {
                    remote: f.client.server.clone(),
                    payload: f.io.take().unwrap(),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(f.client.receive().await.unwrap(), packet);
        }
        f.client.close().await.unwrap();
        assert!(f.closed.load(Ordering::SeqCst));
        assert!(
            shareable,
            "multi-target SS must not allocate a transport per IP target"
        );
    }
}

#[tokio::test]
async fn udp_three_ciphers_pending_cancel_exactly_once_and_close() {
    for name in CIPHERS {
        let mut f = Fixture::new(name, 1500);
        let initial_id = f.client.control.client_session_id;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                f.client.send(request(b"cancelled"))
            )
            .await
            .is_err()
        );
        assert_eq!(f.client.control.packet_id, 1);
        assert!(f.sent.try_recv().is_err());
        assert!(f.client.io.take().is_err());
        f.permits.add_permits(1);
        f.client.send(request(b"once")).await.unwrap();
        let wire = f.sent.recv().await.unwrap();
        let (data, control) = f.decode_request(wire).await;
        assert_eq!(data, b"once");
        assert_eq!(control.client_session_id, initial_id);
        assert_eq!(control.packet_id, 2);
        assert!(f.sent.try_recv().is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(5), f.client.receive())
                .await
                .is_err()
        );
        let reply = f.response(&f.control(1, 1), b"answer").await;
        f.replies.send(reply).await.unwrap();
        let actual = f.client.receive().await.unwrap();
        assert_eq!(actual.remote, target());
        assert_eq!(actual.payload, &b"answer"[..]);
        f.client.close().await.unwrap();
        assert!(f.closed.load(Ordering::SeqCst));
        assert!(f.client.send(request(b"closed")).await.is_err());
        assert!(f.client.receive().await.is_err());
        assert!(f.client.sessions.is_empty());
    }
}

#[tokio::test]
async fn udp_replay_session_restart_wrong_client_and_overflow_are_bounded() {
    for name in CIPHERS {
        let mut f = Fixture::new(name, 1500);
        let one = f.response(&f.control(1, 10), b"one").await;
        f.replies.send(one.clone()).await.unwrap();
        assert_eq!(f.client.receive().await.unwrap().payload, &b"one"[..]);
        f.replies.send(one).await.unwrap(); // replay
        let reordered = f.response(&f.control(1, 9), b"reordered").await;
        f.replies.send(reordered).await.unwrap();
        assert_eq!(f.client.receive().await.unwrap().payload, &b"reordered"[..]);
        let jumped = f.response(&f.control(1, 9000), b"jumped").await;
        f.replies.send(jumped).await.unwrap();
        assert_eq!(f.client.receive().await.unwrap().payload, &b"jumped"[..]);
        for control in [f.control(1, 11), f.control(1, u64::MAX)] {
            f.replies
                .send(f.response(&control, b"invalid").await)
                .await
                .unwrap();
        }
        let mut wrong = f.control(1, 9001);
        wrong.client_session_id ^= 1;
        f.replies
            .send(f.response(&wrong, b"invalid").await)
            .await
            .unwrap();
        f.replies
            .send(f.response(&f.control(2, 1), b"restart").await)
            .await
            .unwrap();
        assert_eq!(f.client.receive().await.unwrap().payload, &b"restart"[..]);
        assert_eq!(f.client.sessions.len(), 2);
        f.replies
            .send(f.response(&f.control(3, 1), b"too-soon").await)
            .await
            .unwrap();
        f.replies
            .send(f.response(&f.control(2, 2), b"current").await)
            .await
            .unwrap();
        assert_eq!(f.client.receive().await.unwrap().payload, &b"current"[..]);
        assert_eq!(f.client.sessions.len(), 2);
        f.client.sessions[0].last = Instant::now() - SESSION_RETENTION;
        f.replies
            .send(f.response(&f.control(3, 1), b"new-session").await)
            .await
            .unwrap();
        assert_eq!(
            f.client.receive().await.unwrap().payload,
            &b"new-session"[..]
        );
        assert_eq!(f.client.sessions[0].id, 2);
        assert_eq!(f.client.sessions[1].id, 3);
        f.client.control.packet_id = u64::MAX - 1;
        let previous = f.client.control.client_session_id;
        f.permits.add_permits(1);
        f.client.send(request(b"rotated")).await.unwrap();
        let wire = f.sent.recv().await.unwrap();
        let (data, control) = f.decode_request(wire).await;
        assert_eq!(data, b"rotated");
        assert_ne!(control.client_session_id, previous);
        assert_eq!(control.packet_id, 1);
        assert!(f.client.sessions.is_empty());
    }
}

#[tokio::test]
async fn udp_invalid_packets_and_limits_do_not_poison_replay_state() {
    for name in CIPHERS {
        for maximum in [1200, 65_000] {
            // TUN-sized and SOCKS5-sized budgets
            let mut f = Fixture::new(name, maximum);
            let mut corrupt = f.response(&f.control(1, 1), b"bad").await;
            let mut bytes = corrupt.payload.to_vec();
            *bytes.last_mut().unwrap() ^= 1;
            corrupt.payload = bytes.into();
            f.replies.send(corrupt).await.unwrap();
            let mut truncated = f.response(&f.control(1, 1), b"short").await;
            truncated.payload = truncated.payload.slice(..10);
            f.replies.send(truncated).await.unwrap();
            let mut spoofed = f.response(&f.control(1, 1), b"spoofed").await;
            spoofed.remote = Destination::Ip("127.0.0.2:12345".parse().unwrap());
            f.replies.send(spoofed).await.unwrap();
            let oversized = f
                .response(&f.control(1, 1), &vec![0x5a; usize::from(maximum) + 1])
                .await;
            f.replies.send(oversized).await.unwrap();
            let exact = f
                .response(&f.control(1, 1), &vec![0x5a; usize::from(maximum)])
                .await;
            f.replies.send(exact).await.unwrap();
            let actual = tokio::time::timeout(Duration::from_secs(1), f.client.receive())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(actual.payload.len(), usize::from(maximum));
            assert!(actual.payload.iter().all(|byte| *byte == 0x5a));
            assert_eq!(f.client.sessions.len(), 1);
            assert!(f.client.io.take().is_err());
        }
    }
}

#[test]
fn packet_handoff_checks_wire_limit_without_truncation_or_overwrite() {
    let io = PacketIo::default();
    assert!(io.put(Bytes::from(vec![0; MAX_WIRE_PACKET + 1])).is_err());
    io.put(Bytes::from(vec![0x5a; MAX_WIRE_PACKET])).unwrap();
    assert!(io.put(Bytes::from_static(b"overwrite")).is_err());
    assert_eq!(io.take().unwrap().len(), MAX_WIRE_PACKET);
    assert!(io.take().is_err());
}

#[tokio::test]
async fn udp_encoded_wire_exact_limit_and_one_over_never_reach_inner_io() {
    for name in CIPHERS {
        let mut f = Fixture::new(name, 65_507);
        // Non-empty payloads have no padding. Determine the actual codec's
        // overhead, then exercise exact wire bounds instead of plaintext bounds.
        f.permits.add_permits(3);
        f.client.send(request(b"x")).await.unwrap();
        let overhead = f.sent.recv().await.unwrap().payload.len() - 1;
        let packet = |length| Datagram {
            remote: target(),
            payload: Bytes::from(vec![0x5a; length]),
            sniffed_domain: None,
        };
        f.client
            .send(packet(MAX_WIRE_PACKET - overhead))
            .await
            .unwrap();
        assert_eq!(f.sent.recv().await.unwrap().payload.len(), MAX_WIRE_PACKET);
        assert!(
            f.client
                .send(packet(MAX_WIRE_PACKET - overhead + 1))
                .await
                .is_err()
        );
        assert!(f.sent.try_recv().is_err());
        assert!(f.client.io.take().is_err());
        // A rejected oversized send neither poisons the slot nor reuses its ID.
        f.client.send(request(b"after-limit")).await.unwrap();
        let sent = f.sent.recv().await.unwrap();
        let (body, control) = f.decode_request(sent).await;
        assert_eq!(body, b"after-limit");
        assert_eq!(control.packet_id, 4);
        let other = Fixture::new(name, 1500);
        assert_ne!(
            f.client.control.client_session_id,
            other.client.control.client_session_id
        );
    }
}
