//! Production PacketUp factory over real H3 and bounded in-memory datagrams.
//! This is a feedback/ownership fixture, not a process-RSS or TUN capacity test.
use super::*;
use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{OutboundConnector, VlessOutbound},
    session::{Datagram, Destination},
    transport::{quic::OwnedRuntime, quinn_h3::tests::memory_socket},
};
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::FutureExt;
use std::{
    future::Future,
    net::SocketAddr,
    panic::{AssertUnwindSafe, resume_unwind},
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const BATCH: usize = 128 * 1024;
const LIMIT: Duration = Duration::from_secs(10);
type Peer = h3::server::Connection<h3_quinn::Connection, Bytes>;
type PeerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Default)]
struct AckGate {
    held: std::sync::atomic::AtomicBool,
    changed: tokio::sync::Notify,
}
impl AckGate {
    fn set(&self, held: bool) {
        self.held.store(held, Ordering::SeqCst);
        self.changed.notify_one();
    }
}

struct Packets {
    send: mpsc::Sender<Bytes>,
    receive: mpsc::Receiver<Bytes>,
    pending: Option<Bytes>,
    gate: Arc<AckGate>,
    peer: SocketAddr,
    closed: Arc<AtomicUsize>,
}
#[async_trait]
impl DatagramTransport for Packets {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1400, 1400)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        assert_eq!(packet.remote, self.peer.into());
        self.send
            .send(packet.payload)
            .await
            .map_err(|_| DispatchError::NotAllowed)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.pending.is_none() {
            self.pending = Some(self.receive.recv().await.ok_or(DispatchError::NotAllowed)?);
        }
        loop {
            let changed = self.gate.changed.notified();
            if !self.gate.held.load(Ordering::SeqCst) {
                break;
            }
            changed.await;
        }
        Ok(Datagram {
            remote: self.peer.into(),
            payload: self.pending.take().unwrap(),
            sniffed_domain: None,
        })
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed.fetch_add(1, Ordering::SeqCst);
        self.pending = None;
        self.receive.close();
        Ok(())
    }
}

struct Fixture {
    client: XHttpClient,
    raw: Option<QuicTransport>,
    gate: Arc<AckGate>,
    native_peer: Option<quinn::Connection>,
    endpoint: quinn::Endpoint,
    runtime: Arc<OwnedRuntime>,
    sender: Option<SendRequest>,
    lease: Option<ConnectionLease>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    closed: Arc<AtomicUsize>,
    download: bool,
}
impl Fixture {
    fn new(client: XHttpClient, download: bool, streams: u32, receive_window: u32) -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    identity.signing_key.serialize_der().into(),
                ),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        Arc::get_mut(&mut server.transport)
            .unwrap()
            .max_concurrent_bidi_streams(streams.into())
            .stream_receive_window(receive_window.into())
            .receive_window((1024_u32 * 1024).into())
            .mtu_discovery_config(None);
        let peer: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let local: SocketAddr = "192.0.2.1:44001".parse().unwrap();
        let (to_server, from_client) = mpsc::channel(32);
        let (to_client, from_server) = mpsc::channel(32);
        let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            memory_socket(to_client, from_client, peer, local),
            runtime.clone(),
        )
        .unwrap();
        let closed = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(AckGate::default());
        Self {
            client,
            gate: gate.clone(),
            native_peer: None,
            endpoint,
            runtime,
            download,
            raw: Some(QuicTransport {
                transport: Box::new(Packets {
                    send: to_server,
                    receive: from_server,
                    pending: None,
                    gate,
                    peer,
                    closed: closed.clone(),
                }),
                peer,
                budget: DatagramBudget::new(1400, 1400),
                tls: Arc::new(client_tls),
                server_name: "localhost".into(),
            }),
            sender: None,
            lease: None,
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            closed,
        }
    }
    async fn initialize(&mut self) -> Peer {
        let raw = self.raw.take().unwrap();
        let (connected, accepted) = tokio::join!(
            self.client.acquire(self.download, || async move {
                Ok(TransportIo::Quic(Box::new(raw)))
            }),
            async { self.endpoint.accept().await.unwrap().await.unwrap() }
        );
        let (sender, lease) = connected.unwrap();
        assert!(
            matches!(&sender, SendRequest::H3(_)),
            "must use the production H3 driver"
        );
        self.sender = Some(sender);
        self.lease = Some(lease);
        self.native_peer = Some(accepted.clone());
        h3::server::builder()
            .max_field_section_size(16 * 1024)
            .build::<_, Bytes>(h3_quinn::Connection::new(accepted))
            .await
            .unwrap()
    }
    fn writer(&self, session: &str) -> packet_up::Writer {
        self.client
            .packet_up_writer(self.sender.as_ref().unwrap().clone(), Arc::from(session))
            .unwrap()
    }
    fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        let cancel = self.cancel.clone();
        self.tasks.push(tokio::spawn(async move {
            tokio::select! { biased; () = cancel.cancelled() => {}, () = future => {} }
        }));
    }
    async fn stop(&mut self) {
        self.gate.set(false);
        // Never abort the managed client driver: it owns nested endpoint,
        // runtime and DatagramTransport retirement. Re-await a timed-out barrier.
        let client_stop = timeout(Duration::from_secs(3), self.client.stop()).await;
        self.cancel.cancel();
        self.endpoint.close(0_u8.into(), b"");
        let peer_idle = timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
        let peer_stop = timeout(Duration::from_secs(2), self.runtime.stop()).await;
        self.client.stop().await;
        self.runtime.stop().await;
        let mut panic = None;
        for task in self.tasks.drain(..) {
            if let Err(error) = task.await {
                if panic.is_none() {
                    panic = Some(error);
                }
            }
        }
        self.lease.take();
        self.sender.take();
        if let Some(error) = panic {
            resume_unwind(error.into_panic());
        }
        assert!(
            client_stop.is_ok(),
            "managed client Stop exceeded its original bound"
        );
        assert!(
            peer_idle.is_ok() && peer_stop.is_ok(),
            "peer retirement exceeded fixture bound"
        );
        assert_eq!(
            self.closed.load(Ordering::SeqCst),
            1,
            "physical datagram owner must close exactly once"
        );
    }
}

fn node(smux: Option<serde_json::Value>, placement: &str, split: bool) -> VlessOutbound {
    let mut raw = serde_json::json!({
        "proxies":[{"name":"fixture", "type":"vless", "server":"example.com", "port":443,
            "uuid":"00000000-0000-0000-0000-000000000001", "tls":true, "alpn":["h3"],
            "network":"xhttp", "xhttp-opts":{"path":"/x", "mode":"packet-up",
                "uplink-data-placement":placement}}], "rules":["MATCH,DIRECT"]
    });
    if let Some(smux) = smux {
        raw["proxies"][0]["smux"] = smux;
    }
    if matches!(placement, "header" | "cookie") {
        raw["proxies"][0]["xhttp-opts"]["uplink-data-key"] = "payload".into();
    }
    if split {
        raw["proxies"][0]["xhttp-opts"]["download-settings"] = serde_json::json!({
            "server":"download.example", "port":8443, "tls":true, "alpn":["h3"]});
    }
    let config = crate::config::Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
    let proxy = &config.proxies[0];
    let crate::config::ProxyProtocol::Vless(settings) = &proxy.protocol else {
        panic!("not VLESS")
    };
    let endpoint = |name: &str, port| crate::dialer::ResolvedEndpoint {
        logical_host: name.into(),
        port,
        addresses: vec![SocketAddr::from(([192, 0, 2, 2], port))],
    };
    let mut node = VlessOutbound::new_with_endpoints(
        settings,
        endpoint("example.com", 443),
        split.then(|| endpoint("download.example", 8443)),
        crate::dialer::Dialer::default(),
    )
    .unwrap();
    node.configure_shared_xhttp_transport(proxy.smux.as_ref());
    node
}
fn shared_node(placement: &str) -> VlessOutbound {
    node(
        Some(
            serde_json::json!({"enabled":true, "protocol":"h2mux", "only-tcp":false,
        "padding":false}),
        ),
        placement,
        false,
    )
}
fn payload(sequence: usize) -> Vec<u8> {
    payload_len(sequence, BATCH)
}
fn payload_len(sequence: usize, length: usize) -> Vec<u8> {
    (0..length).map(|offset| byte(sequence, offset)).collect()
}
fn byte(sequence: usize, offset: usize) -> u8 {
    ((offset + 17 * sequence) % 251) as u8
}
async fn accept(peer: &mut Peer, session: &str, sequence: usize) -> PeerStream {
    let (request, stream) = peer
        .accept()
        .await
        .unwrap()
        .unwrap()
        .resolve_request()
        .await
        .unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), format!("/x/{session}/{sequence}"));
    stream
}
async fn body(stream: &mut PeerStream, sequence: usize) {
    body_len(stream, sequence, BATCH).await;
}
async fn body_len(stream: &mut PeerStream, sequence: usize, length: usize) {
    let mut count = 0;
    while let Some(mut data) = stream.recv_data().await.unwrap() {
        while data.has_remaining() {
            assert!(count < length, "body exceeded its one bounded batch");
            assert_eq!(data.get_u8(), byte(sequence, count));
            count += 1;
        }
    }
    assert_eq!(count, length);
    assert!(stream.recv_trailers().await.unwrap().is_none());
}
async fn respond(stream: &mut PeerStream, status: u16) {
    stream
        .send_response(http::Response::builder().status(status).body(()).unwrap())
        .await
        .unwrap();
    stream.finish().await.unwrap();
}
async fn pending_write(writer: &mut packet_up::Writer) {
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *writer).poll_write(cx, b"third")))
            .await
            .is_pending(),
        "nonempty third write crossed the response bound"
    );
}
async fn pending_flush(writer: &mut packet_up::Writer) {
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *writer).poll_flush(cx)))
            .await
            .is_pending(),
        "unacknowledged bytes crossed strong flush"
    );
}
fn finish(result: Result<Result<(), tokio::time::error::Elapsed>, Box<dyn std::any::Any + Send>>) {
    match result {
        Ok(result) => result.expect("actual H3 feedback fixture timed out"),
        Err(panic) => resume_unwind(panic),
    }
}

#[tokio::test(start_paused = true)]
async fn qualified_default_partial_post_reaches_h3_before_ten_ms_with_strong_receipt() {
    let node = shared_node("body");
    let (client, _) = node.test_xhttp_clients().unwrap();
    let mut fixture = Fixture::new(client, false, 16, 256 * 1024);
    let result = AssertUnwindSafe(timeout(LIMIT, async {
        let mut peer = fixture.initialize().await;
        let (arrived, arrival) = oneshot::channel();
        let (release, released) = oneshot::channel();
        fixture.spawn(async move {
            let mut first = accept(&mut peer, "default-five", 0).await;
            let at = tokio::time::Instant::now();
            body_len(&mut first, 0, 64).await;
            arrived.send(at).unwrap();
            released.await.unwrap();
            respond(&mut first, 200).await;
            let _ = peer.accept().await;
        });
        let mut writer = fixture.writer("default-five");
        let began = tokio::time::Instant::now();
        writer.write_all(&payload_len(0, 64)).await.unwrap();
        let at = arrival.await.unwrap();
        // Real peer headers/body/FIN are observed, not the delay expression.
        // Arrival may include transport service; the preceding 5 ms default
        // cannot pass this bound even when its transport service is immediate.
        let elapsed = at - began;
        assert!(
            elapsed >= Duration::from_millis(2),
            "partial POST bypassed aggregation"
        );
        assert!(
            elapsed < Duration::from_millis(5),
            "qualified default still waited five ms"
        );
        assert_eq!(writer.snapshot().accepted, 64);
        assert_eq!(writer.snapshot().committed, 0);
        pending_flush(&mut writer).await;
        release.send(()).unwrap();
        writer.flush().await.unwrap();
        assert_eq!(writer.snapshot().committed, 64);
        writer.shutdown().await.unwrap();
    }))
    .catch_unwind()
    .await;
    fixture.stop().await;
    node.shutdown().await;
    finish(result);
}

#[tokio::test]
async fn two_held_post_responses_reuse_one_body_backing_and_bound_the_third_write() {
    for placement in ["body", "auto"] {
        let node = shared_node(placement);
        let (client, download) = node.test_xhttp_clients().unwrap();
        assert!(download.is_none());
        let mut fixture = Fixture::new(client, false, 16, 256 * 1024);
        let result = AssertUnwindSafe(timeout(LIMIT, async {
            let mut peer = fixture.initialize().await;
            let (first, arrived_first) = oneshot::channel();
            let (second, arrived_second) = oneshot::channel();
            let (release, released) = oneshot::channel();
            fixture.spawn(async move {
                let mut a = accept(&mut peer, "two", 0).await;
                body(&mut a, 0).await;
                first.send(()).unwrap();
                let mut b = accept(&mut peer, "two", 1).await;
                body(&mut b, 1).await;
                second.send(()).unwrap();
                released.await.unwrap();
                respond(&mut a, 200).await;
                respond(&mut b, 200).await;
                let _ = peer.accept().await;
            });
            let mut writer = fixture.writer("two");
            writer.write_all(&payload(0)).await.unwrap();
            // This immediate read occurs before yielding to the worker in the
            // current-thread runtime. Do not inspect the taken/empty Vec later.
            let first = writer.snapshot();
            assert_eq!(first.buffer_len, BATCH);
            assert_eq!(first.buffer_capacity, BATCH);
            arrived_first.await.unwrap();
            writer.write_all(&payload(1)).await.unwrap();
            let second = writer.snapshot();
            assert_eq!(second.buffer_len, BATCH);
            assert_eq!(second.buffer_capacity, BATCH);
            assert_eq!(
                second.buffer_ptr, first.buffer_ptr,
                "the body backing must be recovered, not copied into a parallel workspace"
            );
            arrived_second.await.unwrap();
            pending_write(&mut writer).await;
            pending_flush(&mut writer).await;
            assert_eq!(writer.snapshot().accepted, (2 * BATCH) as u64);
            assert_eq!(writer.snapshot().committed, 0);
            release.send(()).unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
            assert_eq!(writer.snapshot().committed, (2 * BATCH) as u64);
        }))
        .catch_unwind()
        .await;
        fixture.stop().await;
        node.shutdown().await;
        finish(result);
    }
}

#[tokio::test]
async fn consumed_second_response_cannot_cross_a_failed_first_response_hole() {
    let node = shared_node("body");
    let (client, _) = node.test_xhttp_clients().unwrap();
    let mut fixture = Fixture::new(client, false, 16, 256 * 1024);
    let result = AssertUnwindSafe(timeout(LIMIT, async {
        let mut peer = fixture.initialize().await;
        let (second, arrived_second) = oneshot::channel();
        let (fail_first, failed_first) = oneshot::channel();
        fixture.spawn(async move {
            let mut a = accept(&mut peer, "hole", 0).await;
            body(&mut a, 0).await;
            let mut b = accept(&mut peer, "hole", 1).await;
            body(&mut b, 1).await;
            respond(&mut b, 200).await;
            second.send(()).unwrap();
            failed_first.await.unwrap();
            respond(&mut a, 500).await;
            // A fresh writer on this same live H3 connection is a positive
            // barrier: a replayed failed session would not match this request.
            let mut control = accept(&mut peer, "control", 0).await;
            body(&mut control, 0).await;
            respond(&mut control, 200).await;
            let _ = peer.accept().await;
        });
        let mut writer = fixture.writer("hole");
        writer.write_all(&payload(0)).await.unwrap();
        writer.write_all(&payload(1)).await.unwrap();
        arrived_second.await.unwrap();
        loop {
            let seen = writer.snapshot();
            if seen.ready_out_of_order {
                assert_eq!(seen.occupied_responses, 2);
                assert_eq!(seen.ready_responses, 1);
                assert_eq!(seen.committed, 0);
                break;
            }
            tokio::task::yield_now().await;
        }
        // These are checks after actual response consumption, not a race with
        // an unpolled response future. Pending alone would be insufficient.
        pending_write(&mut writer).await;
        pending_flush(&mut writer).await;
        fail_first.send(()).unwrap();
        let failure = writer.flush().await.unwrap_err();
        assert!(
            failure.to_string().contains("HTTP status 500"),
            "wrong failure: {failure}"
        );
        assert_eq!(writer.snapshot().committed, 0);
        assert!(writer.write_all(b"no replay").await.is_err());
        let mut control = fixture.writer("control");
        control.write_all(&payload(0)).await.unwrap();
        control.flush().await.unwrap();
        control.shutdown().await.unwrap();
    }))
    .catch_unwind()
    .await;
    fixture.stop().await;
    node.shutdown().await;
    finish(result);
}

#[tokio::test]
async fn one_peer_stream_credit_jointly_drives_old_response_and_next_open() {
    let node = shared_node("body");
    let (client, _) = node.test_xhttp_clients().unwrap();
    let mut fixture = Fixture::new(client, false, 1, 256 * 1024);
    let result = AssertUnwindSafe(timeout(LIMIT, async {
        let mut peer = fixture.initialize().await;
        let (first, arrived_first) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (second, arrived_second) = oneshot::channel();
        fixture.spawn(async move {
            let mut a = accept(&mut peer, "credit", 0).await;
            body(&mut a, 0).await;
            first.send(()).unwrap();
            released.await.unwrap();
            respond(&mut a, 200).await;
            drop(a);
            let mut b = accept(&mut peer, "credit", 1).await;
            body(&mut b, 1).await;
            second.send(()).unwrap();
            respond(&mut b, 200).await;
            let _ = peer.accept().await;
        });
        let mut writer = fixture.writer("credit");
        writer.write_all(&payload(0)).await.unwrap();
        arrived_first.await.unwrap();
        writer.write_all(&payload(1)).await.unwrap();
        pending_write(&mut writer).await;
        pending_flush(&mut writer).await;
        release.send(()).unwrap();
        arrived_second.await.unwrap();
        writer.flush().await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(writer.snapshot().committed, (2 * BATCH) as u64);
    }))
    .catch_unwind()
    .await;
    fixture.stop().await;
    node.shutdown().await;
    finish(result);
}

#[tokio::test]
async fn early_rejection_of_a_credit_blocked_body_cancels_and_joins_stop() {
    let node = shared_node("body");
    let (client, _) = node.test_xhttp_clients().unwrap();
    let mut fixture = Fixture::new(client, false, 16, 32 * 1024);
    let result = AssertUnwindSafe(timeout(LIMIT, async {
        let mut peer = fixture.initialize().await;
        let (prefix, saw_prefix) = oneshot::channel();
        let (reject, rejected) = oneshot::channel();
        fixture.spawn(async move {
            let mut a = accept(&mut peer, "early", 0).await;
            let data = a.recv_data().await.unwrap().unwrap();
            let count = data.remaining();
            assert!(count > 0 && count < BATCH);
            drop(data);
            prefix.send(count).unwrap();
            // No further request reads: the 32 KiB stream credit plus that
            // one consumed prefix cannot deliver this full 128 KiB body/FIN.
            rejected.await.unwrap();
            respond(&mut a, 500).await;
            let _ = peer.accept().await;
            drop(a);
        });
        let mut writer = fixture.writer("early");
        writer.write_all(&payload(0)).await.unwrap();
        assert!(saw_prefix.await.unwrap() < BATCH);
        assert!(writer.snapshot().in_flight);
        pending_write(&mut writer).await;
        pending_flush(&mut writer).await;
        reject.send(()).unwrap();
        let failure = writer.flush().await.unwrap_err();
        assert!(
            failure.to_string().contains("HTTP status 500"),
            "early status must be consumed while body is blocked: {failure}"
        );
        fixture.client.stop().await;
        assert!(writer.write_all(b"after Stop").await.is_err());
    }))
    .catch_unwind()
    .await;
    fixture.stop().await;
    node.shutdown().await;
    finish(result);
}

#[tokio::test]
async fn dropping_a_completed_upload_preserves_its_fin_sibling_and_active_stop() {
    let node = shared_node("body");
    let (client, _) = node.test_xhttp_clients().unwrap();
    let mut fixture = Fixture::new(client, false, 16, 256 * 1024);
    let result = AssertUnwindSafe(timeout(LIMIT, async {
        let mut peer = fixture.initialize().await;
        let (first, arrived_first) = oneshot::channel();
        let (check, checked) = oneshot::channel();
        let (fin, fin_checked) = oneshot::channel();
        let (active, arrived_active) = oneshot::channel();
        fixture.spawn(async move {
            let mut a = accept(&mut peer, "drop", 0).await;
            body(&mut a, 0).await;
            first.send(()).unwrap();
            let mut b = accept(&mut peer, "sibling", 0).await;
            body(&mut b, 0).await;
            checked.await.unwrap();
            assert!(
                a.recv_data().await.unwrap().is_none(),
                "completed request FIN became a reset/error"
            );
            fin.send(()).unwrap();
            respond(&mut b, 200).await;
            let mut c = accept(&mut peer, "active", 0).await;
            body(&mut c, 0).await;
            active.send(()).unwrap();
            // Hold both pending responses until the owner's real Stop.
            let _ = peer.accept().await;
            drop((a, c));
        });
        let mut dropped = fixture.writer("drop");
        dropped.write_all(&payload(0)).await.unwrap();
        arrived_first.await.unwrap();
        pending_flush(&mut dropped).await;
        drop(dropped);
        let mut sibling = fixture.writer("sibling");
        sibling.write_all(&payload(0)).await.unwrap();
        check.send(()).unwrap();
        fin_checked.await.unwrap();
        sibling.flush().await.unwrap();
        sibling.shutdown().await.unwrap();
        let mut active = fixture.writer("active");
        active.write_all(&payload(0)).await.unwrap();
        arrived_active.await.unwrap();
        pending_flush(&mut active).await;
        fixture.client.stop().await;
        assert!(active.flush().await.is_err());
        assert!(active.write_all(b"after Stop").await.is_err());
    }))
    .catch_unwind()
    .await;
    fixture.stop().await;
    node.shutdown().await;
    finish(result);
}

async fn serial_post(peer: &mut Peer, placement: &str, sequence: usize) -> PeerStream {
    let (request, mut stream) = peer
        .accept()
        .await
        .unwrap()
        .unwrap()
        .resolve_request()
        .await
        .unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), format!("/x/serial/{sequence}"));
    if placement == "body" {
        body_len(&mut stream, sequence, 64).await;
    } else {
        let encoded = if placement == "header" {
            request
                .headers()
                .get("payload-0")
                .unwrap()
                .to_str()
                .unwrap()
        } else {
            request
                .headers()
                .get(http::header::COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .split("; ")
                .find_map(|entry| entry.strip_prefix("payload_0="))
                .unwrap()
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap();
        assert_eq!(bytes, payload_len(sequence, 64));
        assert!(
            stream.recv_data().await.unwrap().is_none(),
            "metadata payload has no HTTP body"
        );
        assert!(stream.recv_trailers().await.unwrap().is_none());
    }
    stream
}

#[tokio::test]
async fn normalized_ineligible_factories_keep_one_unacknowledged_body() {
    // Small writes avoid conflating the header/cookie request budget with the
    // serial-response gate. Full 128 KiB body geometry is tested separately.
    let shared = || serde_json::json!({"enabled":true,"protocol":"h2mux","only-tcp":false});
    let cases = [
        (None, false, "body"),
        (
            Some(serde_json::json!({"enabled":true,"protocol":"h2mux","only-tcp":true})),
            false,
            "body",
        ),
        (
            Some(serde_json::json!({"enabled":true,"protocol":"h2mux","padding":true})),
            false,
            "body",
        ),
        (
            Some(serde_json::json!({"enabled":true,"protocol":"yamux","only-tcp":false})),
            false,
            "body",
        ),
        (
            Some(serde_json::json!({"enabled":true,"protocol":"smux","only-tcp":false})),
            false,
            "body",
        ),
        (
            Some(serde_json::json!({"enabled":false,"protocol":"h2mux","only-tcp":false})),
            false,
            "body",
        ),
        (Some(shared()), true, "body"),
        (Some(shared()), false, "header"),
        (Some(shared()), false, "cookie"),
    ];
    for (smux, split, placement) in cases {
        let node = node(smux, placement, split);
        let (upload, download) = node.test_xhttp_clients().unwrap();
        for (client, is_download) in
            std::iter::once((upload, false)).chain(download.map(|c| (c, true)))
        {
            let mut fixture = Fixture::new(client, is_download, 16, 256 * 1024);
            let result = AssertUnwindSafe(timeout(LIMIT, async {
                let mut peer = fixture.initialize().await;
                if let SendRequest::H3(sender) = fixture.sender.as_ref().unwrap() {
                    assert!(
                        sender.udp_control.is_none(),
                        "excluded physical got a UDP raise control"
                    );
                }
                let (first, arrived_first) = oneshot::channel();
                let (release, released) = oneshot::channel();
                fixture.spawn(async move {
                    let mut a = serial_post(&mut peer, placement, 0).await;
                    first.send(()).unwrap();
                    released.await.unwrap();
                    respond(&mut a, 200).await;
                    let mut b = serial_post(&mut peer, placement, 1).await;
                    respond(&mut b, 200).await;
                    let _ = peer.accept().await;
                });
                let mut writer = fixture.writer("serial");
                writer.write_all(&payload_len(0, 64)).await.unwrap();
                arrived_first.await.unwrap();
                assert_eq!(writer.snapshot().accepted, 64);
                assert_eq!(writer.snapshot().committed, 0);
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(
                        Pin::new(&mut writer).poll_write(cx, &payload_len(1, 64))
                    ))
                    .await
                    .is_pending(),
                    "ineligible factory admitted a second write while first status was held"
                );
                pending_flush(&mut writer).await;
                release.send(()).unwrap();
                writer.write_all(&payload_len(1, 64)).await.unwrap();
                writer.flush().await.unwrap();
                writer.shutdown().await.unwrap();
                assert_eq!(writer.snapshot().committed, 128);
            }))
            .catch_unwind()
            .await;
            fixture.stop().await;
            if !matches!(&result, Ok(Ok(()))) {
                node.shutdown().await;
                finish(result);
            }
        }
        node.shutdown().await;
    }
}

#[cfg(feature = "interop-test")]
#[path = "h3_udp_budget_memory_tests.rs"]
mod udp_budget;
