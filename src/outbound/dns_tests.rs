use super::*;
use crate::{
    config::Config,
    dispatch::Dispatcher,
    dns::resolution::ResolutionContext,
    dns::{QueryType, RecordData, build_query, parse_response},
    session::{DatagramSession, InboundKind, InboundMetadata},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct NoNetwork(AtomicUsize);

#[async_trait]
impl Dispatcher for NoNetwork {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(DispatchError::NotAllowed)
    }
}

fn context() -> (Arc<RuntimeDns>, EstablishContext, Arc<NoNetwork>) {
    let config = Config::parse_yaml(
        br#"
hosts: {unit.test: 192.0.2.8}
dns:
  enable: true
  use-system-hosts: false
  nameserver: [192.0.2.53]
"#,
    )
    .unwrap();
    let no_network = Arc::new(NoNetwork::default());
    let dns = Arc::new(RuntimeDns::new(&config.dns, no_network.clone()));
    let resolution = ResolutionContext::runtime(false);
    resolution.bind_runtime(Some(&dns)).unwrap();
    (
        dns,
        EstablishContext::with_resolution(Duration::from_secs(10), resolution),
        no_network,
    )
}

fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(8053),
        inbound: InboundKind::Tun,
        source: "192.0.2.10:12345".parse().unwrap(),
        destination: Destination::domain("functional.test", 8053).unwrap(),
        sniffed_domain: None,
    }
}

fn request() -> DatagramRequest {
    DatagramRequest::new(DatagramSession::new(
        InboundKind::InternalDns,
        "192.0.2.10:12345".parse().unwrap(),
    ))
}

fn assert_response(wire: &[u8], id: u16) {
    let response = parse_response(wire).unwrap();
    assert_eq!(response.id, id);
    assert_eq!(response.question.name, "unit.test");
    assert_eq!(
        response.answers[0].data,
        RecordData::A("192.0.2.8".parse().unwrap())
    );
}

#[tokio::test]
async fn named_dns_tcp_reuses_runtime_dns_and_keeps_framing_after_half_close() {
    let (_dns, context, no_network) = context();
    let node = DnsOutbound::default();
    let connected = node.connect_stream(session(), &context).await.unwrap();
    assert_eq!(connected.effective_peer, session().destination);
    let mut stream = connected.io;
    for id in [7, 8] {
        let query = build_query(id, "unit.test", QueryType::A).unwrap();
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();
        if id == 8 {
            stream.shutdown().await.unwrap();
        }
        let length = usize::from(stream.read_u16().await.unwrap());
        let mut response = vec![0; length];
        stream.read_exact(&mut response).await.unwrap();
        assert_response(&response, id);
    }
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    node.shutdown().await;
    assert_eq!(no_network.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn named_dns_udp_preserves_original_peer_and_uses_shared_engine() {
    let (_dns, context, no_network) = context();
    let node = DnsOutbound::default();
    let mut transport = node.open_datagram(request(), &context).await.unwrap();
    for id in [11, 12] {
        let remote = Destination::domain(format!("peer-{id}.test"), 8053).unwrap();
        transport
            .send(Datagram {
                remote: remote.clone(),
                payload: Bytes::from(build_query(id, "unit.test", QueryType::A).unwrap()),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        let response = transport.receive().await.unwrap();
        assert_eq!(response.remote, remote);
        assert_response(&response.payload, id);
    }
    transport.close().await.unwrap();
    node.shutdown().await;
    assert_eq!(no_network.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn named_dns_stop_cancels_idle_relays_and_closes_admission() {
    let (_dns, context, no_network) = context();
    let node = DnsOutbound::default();
    let mut stream = node.connect_stream(session(), &context).await.unwrap().io;
    let mut transport = node.open_datagram(request(), &context).await.unwrap();
    let mut byte = [0];
    let read = stream.read(&mut byte);
    tokio::pin!(read);
    assert!(futures_util::poll!(&mut read).is_pending());
    node.begin_shutdown();
    assert_eq!(read.await.unwrap(), 0);
    assert!(transport.receive().await.is_err());
    assert!(node.connect_stream(session(), &context).await.is_err());
    assert!(node.open_datagram(request(), &context).await.is_err());
    tokio::time::timeout(Duration::from_secs(1), node.shutdown())
        .await
        .unwrap();
    assert_eq!(no_network.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn named_dns_requires_the_running_session_resolver() {
    let node = DnsOutbound::default();
    assert!(
        node.connect_stream(session(), &EstablishContext::default())
            .await
            .is_err()
    );
    assert!(
        node.open_datagram(request(), &EstablishContext::default())
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn dns_reserved_reject_tokens_never_reach_the_physical_dispatcher() {
    for (token, transport) in [("REJECT", "tcp"), ("REJECT", "udp"), ("REJECT-DROP", "udp")] {
        let config = Config::parse_yaml(format!("dns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['{transport}://192.0.2.53#{token}']\n").as_bytes()).unwrap();
        let no_network = Arc::new(NoNetwork::default());
        let dns = RuntimeDns::new(&config.dns, no_network.clone());
        let query = build_query(21, "rejected.test", QueryType::A).unwrap();
        let before = Instant::now();
        let response = dns.exchange(&query).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, 2);
        assert_eq!(no_network.0.load(Ordering::Relaxed), 0);
        assert_eq!(Instant::now(), before);
        dns.shutdown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn dns_drop_tcp_wait_is_cancelled_by_its_resolver_stop_owner() {
    let config = Config::parse_yaml(
        br#"
dns:
  enable: true
  use-system-hosts: false
  nameserver: ['tcp://192.0.2.53#REJECT-DROP']
"#,
    )
    .unwrap();
    let no_network = Arc::new(NoNetwork::default());
    let dns = RuntimeDns::new(&config.dns, no_network.clone());
    let query = build_query(22, "rejected.test", QueryType::A).unwrap();
    let exchange = dns.exchange(&query);
    tokio::pin!(exchange);
    assert!(futures_util::poll!(&mut exchange).is_pending());
    let stopped = Instant::now();
    dns.begin_shutdown();
    let response = exchange.await.unwrap();
    assert_eq!(parse_response(&response).unwrap().rcode, 2);
    assert_eq!(Instant::now(), stopped);
    assert_eq!(no_network.0.load(Ordering::Relaxed), 0);
    dns.shutdown().await;
}
