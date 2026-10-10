use super::*;
use crate::dispatch::DatagramTransport;
use crate::dns::{build_wire_query, https_ech_config, source::*};
use async_trait::async_trait;

fn ech_rdata(priority: u16, value: &[u8]) -> Vec<u8> {
    let mut data = priority.to_be_bytes().to_vec();
    data.push(0); // uncompressed TargetName root
    data.extend_from_slice(&5u16.to_be_bytes());
    data.extend_from_slice(&(value.len() as u16).to_be_bytes());
    data.extend_from_slice(value);
    data
}
fn response(query: &[u8], records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    wire[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for (kind, data) in records {
        wire.extend_from_slice(&[0xc0, 0x0c]);
        wire.extend_from_slice(&kind.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
        wire.extend_from_slice(data);
    }
    wire
}
#[test]
fn https_ech_extracts_first_wire_record_and_binary_parameter() {
    let query = build_wire_query(7, "ech.example", 65).unwrap();
    let value = vec![0xfe, 0, 0xff, 0x80];
    let wire = response(
        &query,
        &[
            (64, ech_rdata(1, b"svcb-is-not-an-https-answer")),
            (65, ech_rdata(20, &value)),
            (65, ech_rdata(1, b"lower-priority-is-later")),
        ],
    );
    assert_eq!(https_ech_config(&query, &wire).unwrap(), value);
    assert!(https_ech_config(&query, &response(&query, &[(64, ech_rdata(1, b"x"))])).is_err());
}
#[test]
fn https_ech_rejects_malformed_target_parameters_and_response_identity() {
    let query = build_wire_query(7, "ech.example", 65).unwrap();
    let valid = ech_rdata(1, b"key");
    let mut duplicate = valid.clone();
    duplicate.extend_from_slice(&[0, 5, 0, 0]);
    let mut decreasing = valid.clone();
    decreasing.extend_from_slice(&[0, 1, 0, 0]);
    let compressed = vec![0, 1, 0xc0, 0x0c, 0, 5, 0, 1, 7];
    let mut truncated = valid.clone();
    truncated.pop();
    for data in [duplicate, decreasing, compressed, truncated] {
        assert!(https_ech_config(&query, &response(&query, &[(65, data)])).is_err());
    }
    let mut wire = response(&query, &[(65, valid)]);
    wire[0] ^= 1;
    assert!(https_ech_config(&query, &wire).is_err());
}

#[derive(Default)]
struct Egress {
    calls: AtomicUsize,
    active: Arc<AtomicUsize>,
    queries: Arc<StdMutex<Vec<(Destination, super::super::WireQuestion)>>>,
    records: Vec<(u16, Vec<u8>)>,
    pending: bool,
}
#[async_trait]
impl Dispatcher for Egress {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(Transport {
            active: self.active.clone(),
            queries: self.queries.clone(),
            records: self.records.clone(),
            query: None,
            pending: self.pending,
        }))
    }
}
struct Transport {
    active: Arc<AtomicUsize>,
    queries: Arc<StdMutex<Vec<(Destination, super::super::WireQuestion)>>>,
    records: Vec<(u16, Vec<u8>)>,
    query: Option<Datagram>,
    pending: bool,
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}
#[async_trait]
impl DatagramTransport for Transport {
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        let parsed = classify_query(&datagram.payload).unwrap();
        self.queries
            .lock()
            .unwrap()
            .push((datagram.remote.clone(), parsed.question));
        self.query = Some(datagram);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.pending {
            return std::future::pending().await;
        }
        let query = self.query.take().unwrap();
        Ok(Datagram {
            remote: query.remote,
            payload: Bytes::from(response(&query.payload, &self.records)),
            sniffed_domain: None,
        })
    }
}
fn configuration(enabled: bool) -> crate::config::Config {
    crate::config::Config::parse_yaml(format!("mixed-port: 1080\nhosts: {{query.example: 192.0.2.44}}\ndns:\n  enable: {enabled}\n  use-system-hosts: false\n  enhanced-mode: fake-ip\n  nameserver: [192.0.2.53]\n  proxy-server-nameserver: [203.0.113.53]\n").as_bytes()).unwrap()
}
fn source_snapshot(server: Option<&str>) -> DnsNetworkUpdate {
    DnsNetworkUpdate {
        generation: 1,
        system: server
            .into_iter()
            .map(|address| SystemDnsServer {
                address: address.parse().unwrap(),
                interface: "physical0".into(),
                scope_id: 0,
                requires_encryption: false,
            })
            .collect(),
        dhcp: vec![],
    }
}
fn context(dns: &Arc<RuntimeDns>) -> super::super::resolution::ResolutionContext {
    let context = super::super::resolution::ResolutionContext::runtime(false);
    context.bind_runtime(Some(dns)).unwrap();
    context
}
#[tokio::test]
async fn dynamic_ech_uses_proxy_role_bypasses_hosts_and_reuses_wire_cache() {
    let egress = Arc::new(Egress {
        records: vec![(65, ech_rdata(1, b"binary-config"))],
        ..Default::default()
    });
    let dns = Arc::new(RuntimeDns::new(&configuration(true).dns, egress.clone()));
    let context = context(&dns);
    for _ in 0..2 {
        assert_eq!(
            context
                .resolve_ech(
                    "query.example",
                    TokioInstant::now() + Duration::from_secs(1)
                )
                .await
                .unwrap(),
            b"binary-config"
        );
    }
    assert_eq!(egress.calls.load(Ordering::Relaxed), 1);
    let queries = egress.queries.lock().unwrap();
    assert_eq!(
        queries[0].0,
        Destination::Ip("203.0.113.53:53".parse().unwrap())
    );
    assert_eq!(queries[0].1.query_type, 65);
    assert_eq!(queries[0].1.name, "query.example");
    assert_eq!(egress.active.load(Ordering::Relaxed), 0);
}
#[tokio::test(start_paused = true)]
async fn dynamic_ech_deadline_and_stop_release_query_transport_and_flight() {
    for enabled in [true, false] {
        for stop in [false, true] {
            let egress = Arc::new(Egress {
                pending: true,
                ..Default::default()
            });
            let dns = Arc::new(RuntimeDns::new(&configuration(enabled).dns, egress.clone()));
            if !enabled {
                dns.sources
                    .replace(source_snapshot(Some("192.0.2.99")))
                    .await
                    .unwrap();
            }
            let context = context(&dns);
            let task = tokio::spawn({
                let context = context.clone();
                async move {
                    context
                        .resolve_ech(
                            "pending.example",
                            TokioInstant::now() + Duration::from_millis(50),
                        )
                        .await
                }
            });
            while egress.active.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
            if stop {
                context.close();
            } else {
                tokio::time::advance(Duration::from_millis(50)).await;
            }
            let error = task.await.unwrap().unwrap_err();
            assert_eq!(
                error.kind(),
                if stop {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            assert_eq!(egress.active.load(Ordering::Relaxed), 0);
            let role = if enabled {
                dns.proxy_resolver.as_ref().unwrap()
            } else {
                dns.ech_system_resolver.as_ref().unwrap()
            };
            assert_eq!(role.tcp_pool.http2.is_closed(), stop);
            assert_eq!(role.resource_stats.snapshot().dns_current, 0);
            assert_eq!(role.singleflight.len(), 0);
        }
    }
}

#[tokio::test]
async fn disabled_dns_and_measurement_ech_require_physical_system_metadata() {
    let egress = Arc::new(Egress {
        records: vec![(65, ech_rdata(1, b"system-config"))],
        ..Default::default()
    });
    let dns = Arc::new(RuntimeDns::new(&configuration(false).dns, egress.clone()));
    dns.sources
        .replace(source_snapshot(Some("192.0.2.99")))
        .await
        .unwrap();
    assert_eq!(
        context(&dns)
            .resolve_ech("ech.example", TokioInstant::now() + Duration::from_secs(1))
            .await
            .unwrap(),
        b"system-config"
    );
    assert_eq!(
        egress.queries.lock().unwrap()[0].0,
        Destination::Ip("192.0.2.99:53".parse().unwrap())
    );
    let unavailable = Arc::new(RuntimeDns::new(&configuration(false).dns, egress.clone()));
    unavailable
        .sources
        .replace(source_snapshot(None))
        .await
        .unwrap();
    assert!(
        context(&unavailable)
            .resolve_ech("ech.example", TokioInstant::now() + Duration::from_secs(1))
            .await
            .is_err()
    );
    assert_eq!(egress.calls.load(Ordering::Relaxed), 1);
    let measurement = super::super::resolution::ResolutionContext::measurement(
        Arc::new(crate::dialer::SystemResolver),
        false,
    );
    measurement.bind_measurement_ech(&dns).unwrap();
    assert_eq!(
        measurement
            .resolve_ech("ech.example", TokioInstant::now() + Duration::from_secs(1))
            .await
            .unwrap(),
        b"system-config"
    );
    drop(dns);
    assert!(
        measurement
            .resolve_ech("ech.example", TokioInstant::now() + Duration::from_secs(1))
            .await
            .is_err()
    );
    let dialer = crate::dialer::Dialer::default();
    let leaf = RuntimeDns::measurement_ech(dialer.clone(), crate::security::SecurityContext::new());
    assert!(Arc::ptr_eq(&leaf.sources, &dialer.dns_sources()));
    assert!(matches!(
        leaf.nameservers[0].address,
        DnsAddress::Source(crate::config::DnsSource::System)
    ));
    assert_eq!(leaf.tcp_pool.max_idle, 0);
    assert_eq!(leaf.tcp_pool.stats.idle_limit, 0);
}
