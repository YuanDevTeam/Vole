//! Native endpoint/state-machine fixtures; no sockets or external peers.
use std::{
    any::Any,
    collections::HashSet,
    sync::{Arc, Mutex},
};

use super::*;
use crate::congestion::{
    Controller, ControllerFactory, CubicConfig, FeedbackBatch, PacingPolicy, PacketFeedback,
    PacketInfo,
};

#[derive(Default)]
struct Log {
    sent: Vec<PacketInfo>,
    feedback: Vec<(u64, PacketFeedback)>,
    batches: Vec<FeedbackBatch>,
    outstanding: HashSet<u64>,
    pacing: Option<PacingPolicy>,
}
struct RecorderFactory(Arc<Mutex<Log>>);
impl ControllerFactory for RecorderFactory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Recorder {
            inner: Arc::new(CubicConfig::default()).build(now, mtu),
            log: self.0.clone(),
        })
    }
}
struct Recorder {
    inner: Box<dyn Controller>,
    log: Arc<Mutex<Log>>,
}
impl Controller for Recorder {
    fn pacing_policy(&self) -> Option<PacingPolicy> {
        self.log.lock().unwrap().pacing
    }
    fn packet_feedback_enabled(&self) -> bool {
        true
    }
    fn on_packet_sent(&mut self, packet: PacketInfo, _: u64, _: bool) {
        let mut log = self.log.lock().unwrap();
        if packet.ack_eliciting && packet.congestion_bytes > 0 {
            assert!(log.outstanding.insert(packet.sample_id));
        }
        log.sent.push(packet);
    }
    fn on_packet_feedback(&mut self, _: Instant, packet: PacketInfo, feedback: PacketFeedback) {
        let mut log = self.log.lock().unwrap();
        log.outstanding.remove(&packet.sample_id);
        log.feedback.push((packet.sample_id, feedback));
    }
    fn on_feedback_end(&mut self, _: Instant, batch: FeedbackBatch, _: &RttEstimator) {
        self.log.lock().unwrap().batches.push(batch);
    }
    fn on_sent(&mut self, now: Instant, bytes: u64, packet: u64) {
        self.inner.on_sent(now, bytes, packet);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
    ) {
        self.inner.on_ack(now, sent, bytes, limited, rtt);
    }
    fn on_end_acks(&mut self, now: Instant, flight: u64, limited: bool, packet: Option<u64>) {
        self.inner.on_end_acks(now, flight, limited, packet);
    }
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost: u64) {
        self.inner.on_congestion_event(now, sent, persistent, lost);
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.inner.on_mtu_update(mtu);
    }
    fn window(&self) -> u64 {
        self.inner.window()
    }
    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            log: self.log.clone(),
        })
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[test]
fn vole_packet_feedback_explicit_pacing_limits_actual_endpoint_transmission() {
    let log = Arc::new(Mutex::new(Log {
        pacing: Some(PacingPolicy {
            rate_bytes_per_second: 1_200,
            burst_bytes: 1_200,
            min_delay: Duration::from_millis(1),
        }),
        ..Default::default()
    }));
    let mut pair = Pair::default();
    let mut config = client_config();
    let mut policy = transport(&log);
    Arc::get_mut(&mut policy)
        .unwrap()
        .mtu_discovery_config(None);
    config.transport = policy;
    let (client, _) = pair.connect_with(config);
    let start = pair.time;
    let before = log.lock().unwrap().sent.len();
    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    pair.client_send(client, stream).write(&[3; 8_192]).unwrap();
    pair.client_send(client, stream).finish().unwrap();
    pair.drive();
    let log = log.lock().unwrap();
    let last = log.sent[before..]
        .iter()
        .filter(|packet| packet.ack_eliciting && packet.congestion_bytes > 0)
        .map(|packet| packet.time_sent)
        .max()
        .unwrap();
    assert!(
        last.duration_since(start) >= Duration::from_secs(4),
        "explicit rate was not consumed by the transmission path"
    );
}
fn transport(log: &Arc<Mutex<Log>>) -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.congestion_controller_factory(Arc::new(RecorderFactory(log.clone())));
    config.deterministic_packet_numbers(true);
    Arc::new(config)
}

#[test]
fn vole_packet_feedback_spans_spaces_and_finishes_ack_loss_before_reporting_batch() {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut pair = Pair::default();
    let mut config = client_config();
    config.transport = transport(&log);
    let (client, _) = pair.connect_with(config);
    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    pair.client_send(client, stream)
        .write(&[7; 64 * 1024])
        .unwrap();
    pair.client_send(client, stream).finish().unwrap();
    pair.drive_client();
    // A dropped wire datagram drives actual QUIC packet-threshold loss and retransmission.
    assert!(pair.server.inbound.pop_front().is_some());
    pair.drive();
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    let log = log.lock().unwrap();
    assert!(log
        .sent
        .windows(2)
        .all(|packets| packets[0].sample_id < packets[1].sample_id));
    assert!(log
        .sent
        .iter()
        .any(|packet| packet.space == packet::SpaceId::Initial));
    assert!(log
        .sent
        .iter()
        .any(|packet| packet.space == packet::SpaceId::Handshake));
    assert!(log
        .sent
        .iter()
        .any(|packet| packet.space == packet::SpaceId::Data));
    assert!(log.sent.iter().any(|left| log
        .sent
        .iter()
        .any(|right| left.packet_number == right.packet_number
            && left.space != right.space
            && left.sample_id != right.sample_id)));
    assert!(log
        .feedback
        .iter()
        .any(|(_, feedback)| *feedback == PacketFeedback::Acked));
    assert!(log
        .feedback
        .iter()
        .any(|(_, feedback)| *feedback == PacketFeedback::Lost));
    assert!(log
        .feedback
        .iter()
        .any(|(_, feedback)| *feedback == PacketFeedback::Discarded));
    assert!(log
        .batches
        .iter()
        .any(|batch| batch.acked_bytes > 0 && batch.lost_bytes > 0));
    assert!(log.batches.iter().any(|batch| batch.rtt_updated));
    assert!(
        log.outstanding.is_empty(),
        "sampler entries survived close/key discard"
    );
}

#[test]
fn vole_packet_feedback_migration_discards_old_path_samples_and_preserves_ids() {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut server = server_config();
    server.transport = transport(&log);
    let mut pair = Pair::new(Arc::default(), server);
    let (_, server) = pair.connect();
    pair.server_conn_mut(server).ping();
    pair.drive_server();
    let old_sample = log
        .lock()
        .unwrap()
        .sent
        .iter()
        .rev()
        .find(|packet| {
            packet.path_generation == 0 && packet.ack_eliciting && packet.congestion_bytes > 0
        })
        .unwrap()
        .sample_id;
    // Hold an old-path datagram while the peer validates its new address.
    let held = std::mem::take(&mut pair.client.inbound);
    pair.client.addr.set_port(pair.client.addr.port() + 1);
    let client = *pair.client.connections.keys().next().unwrap();
    pair.client_conn_mut(client).local_address_changed();
    pair.drive();
    for (_, ecn, data) in held {
        pair.client.inbound.push_back((pair.time, ecn, data));
    }
    pair.drive();
    let now = pair.time;
    pair.server_conn_mut(server)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    let log = log.lock().unwrap();
    assert!(log.sent.iter().any(|packet| packet.path_generation > 0));
    assert!(log
        .sent
        .windows(2)
        .all(|packets| packets[0].sample_id < packets[1].sample_id));
    assert!(log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample == old_sample && *feedback == PacketFeedback::Discarded));
    assert!(!log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample == old_sample && *feedback != PacketFeedback::Discarded));
    assert!(
        log.outstanding.is_empty(),
        "sampler entries survived migration/close"
    );
}

#[test]
fn vole_packet_feedback_retry_neuters_inferred_ack_without_reusing_samples() {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let mut config = client_config();
    config.transport = transport(&log);
    let client = pair.begin_connect(config);
    pair.drive_client();
    let initial = log.lock().unwrap().sent[0].sample_id;
    pair.drive_server();
    pair.drive_client();
    {
        let log = log.lock().unwrap();
        assert!(
            log.feedback
                .iter()
                .any(|(sample, feedback)| *sample == initial
                    && *feedback == PacketFeedback::Discarded)
        );
        assert!(!log
            .feedback
            .iter()
            .any(|(sample, feedback)| *sample == initial && *feedback == PacketFeedback::Acked));
        assert!(log
            .sent
            .windows(2)
            .all(|packets| packets[0].sample_id < packets[1].sample_id));
    }
    pair.drive();
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    assert!(log.lock().unwrap().outstanding.is_empty());
}

#[test]
fn vole_packet_feedback_path_reset_neuters_late_ack_before_new_controller_sampling() {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut pair = Pair::default();
    let mut config = client_config();
    config.transport = transport(&log);
    let (client, _) = pair.connect_with(config);
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    let old = log
        .lock()
        .unwrap()
        .sent
        .iter()
        .rev()
        .find(|packet| packet.ack_eliciting && packet.congestion_bytes > 0)
        .unwrap()
        .sample_id;
    // The old wire packet is still awaiting delivery/ACK when the model resets.
    let now = pair.time;
    pair.client_conn_mut(client).path_changed(now);
    pair.drive();
    pair.client_conn_mut(client).ping();
    pair.drive();
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    let log = log.lock().unwrap();
    assert!(log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample == old && *feedback == PacketFeedback::Discarded));
    assert!(!log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample == old && *feedback != PacketFeedback::Discarded));
    assert!(log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample > old && *feedback == PacketFeedback::Acked));
    assert!(log.outstanding.is_empty());
}

#[test]
fn vole_packet_feedback_zero_rtt_rejection_discards_early_data_samples() {
    let log = Arc::new(Mutex::new(Log::default()));
    let server = ServerConfig::with_crypto(Arc::new(server_crypto_with_alpn(vec![
        "first".into(),
        "second".into(),
    ])));
    let mut pair = Pair::new(Arc::default(), server);
    let mut crypto = Arc::new(client_crypto_with_alpn(vec!["first".into()]));
    let mut config = ClientConfig::new(crypto.clone());
    config.transport = transport(&log);
    let client = pair.begin_connect(config);
    pair.drive();
    pair.server.assert_accept();
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    pair.client.connections.clear();
    pair.server.connections.clear();
    assert!(log.lock().unwrap().outstanding.is_empty());
    *log.lock().unwrap() = Log::default();
    // Retain TLS session tickets while changing ALPN, which rejects early data.
    Arc::get_mut(&mut Arc::get_mut(&mut crypto).unwrap().inner)
        .unwrap()
        .alpn_protocols = vec!["second".into()];
    let mut config = ClientConfig::new(crypto);
    config.transport = transport(&log);
    let client = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client).has_0rtt());
    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    pair.client_send(client, stream)
        .write(b"early-data")
        .unwrap();
    pair.drive_client();
    let early = log
        .lock()
        .unwrap()
        .sent
        .iter()
        .find(|packet| packet.space == packet::SpaceId::Data && packet.ack_eliciting)
        .unwrap()
        .sample_id;
    pair.drive();
    assert!(!pair.client_conn_mut(client).accepted_0rtt());
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    let log = log.lock().unwrap();
    assert!(log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample == early && *feedback == PacketFeedback::Discarded));
    assert!(!log
        .feedback
        .iter()
        .any(|(sample, feedback)| *sample == early && *feedback == PacketFeedback::Acked));
    assert!(log.outstanding.is_empty());
}
