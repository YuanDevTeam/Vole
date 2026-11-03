//! Shared probe scheduling and automatic group selection for one resource generation.
use super::*;
use crate::{
    config::{HealthCheckConfig, status_ranges},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    resource::{
        control::{DelayRequest, ProbeError},
        probe::{self, Target},
    },
    session::{DatagramSession, StreamSession},
};
use futures_util::{StreamExt, stream};
use std::{collections::BTreeMap, sync::Mutex};
use tokio::time::Instant;

#[derive(Debug)]
pub(super) struct Activity(Mutex<Instant>);
impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Instant::now())))
    }
    fn touch(&self) {
        *self.0.lock().unwrap() = Instant::now();
    }
    fn active(&self, interval: Duration) -> bool {
        self.0.lock().unwrap().elapsed() < interval
    }
}
pub(super) struct ActiveDispatcher {
    pub dispatcher: Arc<dyn Dispatcher>,
    pub activity: Arc<Activity>,
}
#[async_trait::async_trait]
impl Dispatcher for ActiveDispatcher {
    fn supports_udp(&self) -> bool {
        self.dispatcher.supports_udp()
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        if session.inbound != crate::session::InboundKind::InternalMeasure {
            self.activity.touch();
        }
        self.dispatcher.connect_tcp(session).await
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.activity.touch();
        self.dispatcher.open_datagram(session).await
    }
}
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct Sample {
    pub alive: bool,
    pub delay: u64,
    pub time: u64,
    #[serde(skip)]
    order: u64,
    #[serde(skip)]
    status: Option<u16>,
}
struct Job {
    spec: HealthCheckConfig,
    members: Vec<String>,
    group: Option<usize>,
    last: Option<Instant>,
    provider: Option<String>,
}
pub(super) struct HealthRuntime {
    security: SecurityContext,
    jobs: Mutex<Vec<Job>>,
    samples: Mutex<BTreeMap<(String, String), Sample>>,
    manual_samples: Mutex<BTreeMap<String, Sample>>,
    sequence: std::sync::atomic::AtomicU64,
    probe_slots: tokio::sync::Semaphore,
    groups: Arc<ProxyGroups>,
    targets: RouteTargetDispatchers,
    direct: Arc<dyn Dispatcher>,
    names: BTreeMap<String, RouteTargetId>,
    activity: BTreeMap<String, Arc<Activity>>,
    unified: bool,
    dns: Option<Arc<RuntimeDns>>,
    ipv6: bool,
}
impl HealthRuntime {
    pub fn new(
        config: &Config,
        groups: Arc<ProxyGroups>,
        targets: RouteTargetDispatchers,
        direct: Arc<dyn Dispatcher>,
        activity: Vec<Arc<Activity>>,
        dns: Option<Arc<RuntimeDns>>,
        security: SecurityContext,
    ) -> Arc<Self> {
        let mut jobs = Vec::new();
        for (i, group) in config.proxy_groups.iter().enumerate() {
            jobs.push(Job {
                spec: group.health.clone(),
                members: group
                    .members
                    .iter()
                    .map(|member| member.name.clone())
                    .collect(),
                group: Some(i),
                last: None,
                provider: None,
            });
        }
        if let Some(template) = &config.providers {
            for (name, spec) in &template.proxies {
                let mut health = spec.health_check.clone();
                if health.enable && health.interval == 0 {
                    health.interval = 300;
                }
                jobs.push(Job {
                    spec: health,
                    members: config
                        .provider_members
                        .get(name)
                        .cloned()
                        .unwrap_or_default(),
                    group: None,
                    last: None,
                    provider: Some(name.clone()),
                });
            }
        }
        let mut names = BTreeMap::new();
        for (i, node) in config.proxies.iter().enumerate() {
            names.insert(
                node.tag.clone(),
                RouteTargetId::Proxy(crate::config::ProxyId::new(i).unwrap()),
            );
        }
        for (i, group) in config.proxy_groups.iter().enumerate() {
            names.insert(
                group.name.clone(),
                RouteTargetId::Group(crate::config::ProxyGroupId::new(i).unwrap()),
            );
        }
        let activity = config
            .proxies
            .iter()
            .map(|proxy| proxy.tag.clone())
            .zip(activity)
            .collect();
        Arc::new(Self {
            security,
            jobs: Mutex::new(jobs),
            samples: Mutex::new(BTreeMap::new()),
            manual_samples: Mutex::new(BTreeMap::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
            probe_slots: tokio::sync::Semaphore::new(10),
            groups,
            targets,
            direct,
            names,
            activity,
            unified: config.unified_delay,
            dns,
            ipv6: config.ipv6,
        })
    }
    pub fn states(&self) -> serde_json::Value {
        let samples = self.samples.lock().unwrap();
        let mut nodes = self
            .names
            .iter()
            .filter(|(_, target)| matches!(target, RouteTargetId::Proxy(_)))
            .map(|(name, _)| {
                (
                    name.clone(),
                    serde_json::json!({"name":name,"alive":true,"history":[]}),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (name, kind) in [
            ("DIRECT", "Direct"),
            ("COMPATIBLE", "Compatible"),
            ("REJECT", "Reject"),
            ("REJECT-DROP", "RejectDrop"),
            ("PASS", "Pass"),
            ("PASS-RULE", "PassRule"),
        ] {
            nodes.insert(
                name.to_owned(),
                serde_json::json!({"name":name,"type":kind,"alive":true,"history":[]}),
            );
        }
        let manual = self.manual_samples.lock().unwrap();
        let mut latest = BTreeMap::<&str, &Sample>::new();
        for (name, sample) in samples
            .iter()
            .map(|((name, _), s)| (name.as_str(), s))
            .chain(manual.iter().map(|(name, s)| (name.as_str(), s)))
        {
            if latest.get(name).is_none_or(|old| old.order < sample.order) {
                latest.insert(name, sample);
            }
        }
        for (name, sample) in latest {
            let node = nodes
                .entry(name.to_owned())
                .or_insert_with(|| serde_json::json!({"name":name}));
            node["alive"] = serde_json::json!(sample.alive);
            node["history"] = serde_json::json!([{"time":sample.time,"delay":sample.delay}]);
        }
        serde_json::json!(nodes)
    }
    fn sample(&self, result: &Result<probe::Observation, ProbeError>) -> Sample {
        Sample {
            alive: result.is_ok(),
            delay: result.as_ref().map_or(0, |sample| sample.delay),
            status: result.as_ref().ok().map(|sample| sample.status),
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            order: self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    async fn run_probe(
        &self,
        name: &str,
        request: &DelayRequest,
        cancel: &CancellationToken,
    ) -> Result<probe::Observation, ProbeError> {
        let action = match name {
            "DIRECT" | "COMPATIBLE" => crate::config::RuleAction::Direct,
            "REJECT" | "PASS" | "PASS-RULE" => crate::config::RuleAction::Reject,
            "REJECT-DROP" => crate::config::RuleAction::RejectDrop,
            _ => {
                crate::config::RuleAction::Route(*self.names.get(name).ok_or(ProbeError::NotFound)?)
            }
        };
        if request.timeout.is_zero() {
            return Err(ProbeError::Timeout);
        }
        let operation = async {
            let _slot = self
                .probe_slots
                .acquire()
                .await
                .map_err(|_| ProbeError::Stopped)?;
            let target = Target::parse(&request.url).map_err(|_| ProbeError::Failed)?;
            let rules = RuleSet::compile(vec![crate::config::RuleSpec {
                kind: crate::config::RuleKind::Match,
                action,
                no_resolve: false,
            }])
            .expect("health route");
            let dispatcher = Arc::new(RoutingDispatcher::new_with_ipv6(
                self.targets.clone(),
                self.direct.clone(),
                self.dns.clone(),
                self.ipv6,
                rules,
                Arc::new(crate::routing::EmptyGeoMatcher),
            ));
            probe::observe(
                &target,
                dispatcher,
                request.timeout,
                self.unified,
                &request.expected,
                cancel,
                &self.security,
            )
            .await
            .map_err(|error| match error.kind() {
                io::ErrorKind::TimedOut => ProbeError::Timeout,
                io::ErrorKind::Interrupted => ProbeError::Stopped,
                _ => ProbeError::Failed,
            })
        };
        tokio::select! { biased;
            () = cancel.cancelled() => Err(ProbeError::Stopped),
            result = tokio::time::timeout(request.timeout, operation) => result.map_err(|_| ProbeError::Timeout)?,
        }
    }

    fn record_manual(
        &self,
        name: &str,
        url: &str,
        result: &Result<probe::Observation, ProbeError>,
    ) {
        let sample = self.sample(result);
        self.manual_samples
            .lock()
            .unwrap()
            .insert(name.to_owned(), sample.clone());
        let configured = self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .any(|job| job.spec.url == url && job.members.iter().any(|member| member == name));
        if configured {
            self.samples
                .lock()
                .unwrap()
                .insert((name.to_owned(), url.to_owned()), sample);
        }
    }

    pub async fn node_delay(
        &self,
        name: &str,
        request: &DelayRequest,
        cancel: &CancellationToken,
    ) -> Result<u64, ProbeError> {
        let result = self.run_probe(name, request, cancel).await;
        if !cancel.is_cancelled() && result != Err(ProbeError::NotFound) {
            self.record_manual(name, &request.url, &result);
            self.apply_group_health();
        }
        result.map(|sample| sample.delay)
    }

    pub async fn group_delay(
        &self,
        name: &str,
        request: &DelayRequest,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<String, u64>, ProbeError> {
        let state = self.groups.state(name).map_err(|_| ProbeError::NotFound)?;
        let configured_url = if state.kind == crate::config::GroupKind::UrlTest {
            self.names.get(name).and_then(|target| {
                let RouteTargetId::Group(id) = target else {
                    return None;
                };
                self.jobs
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|job| job.group == Some(id.index()))
                    .map(|job| job.spec.url.clone())
            })
        } else {
            None
        };
        let request = DelayRequest {
            url: configured_url.unwrap_or_else(|| request.url.clone()),
            timeout: request.timeout,
            expected: request.expected.clone(),
        };
        let request = &request;
        let work = state.all.into_iter().map(|name| async move {
            let result = self.run_probe(&name, request, cancel).await;
            if !cancel.is_cancelled() {
                self.record_manual(&name, &request.url, &result);
            }
            (name, result)
        });
        let operation = async {
            let mut results = stream::iter(work).buffer_unordered(10);
            let mut delays = BTreeMap::new();
            while let Some((name, result)) = results.next().await {
                if let Ok(delay) = result {
                    delays.insert(name, delay.delay);
                }
            }
            self.apply_group_health();
            if delays.is_empty() {
                Err(ProbeError::Timeout)
            } else {
                Ok(delays)
            }
        };
        tokio::select! { biased;
            () = cancel.cancelled() => Err(ProbeError::Stopped),
            result = tokio::time::timeout(request.timeout, operation) => result.map_err(|_| ProbeError::Timeout)?,
        }
    }

    pub async fn provider_healthcheck(
        &self,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let (spec, members) = self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .find(|job| job.provider.as_deref() == Some(name))
            .map(|job| (job.spec.clone(), job.members.clone()))
            .ok_or(ProbeError::NotFound)?;
        if spec.url.is_empty() {
            return Ok(());
        }
        let request = DelayRequest {
            url: spec.url,
            timeout: Duration::from_millis(if spec.timeout == 0 {
                5000
            } else {
                spec.timeout
            }),
            expected: status_ranges(&spec.expected_status).expect("validated provider health"),
        };
        let work = members.into_iter().map(|name| async {
            let result = self.run_probe(&name, &request, cancel).await;
            if !cancel.is_cancelled() {
                self.samples
                    .lock()
                    .unwrap()
                    .insert((name, request.url.clone()), self.sample(&result));
            }
        });
        let mut results = stream::iter(work).buffer_unordered(10);
        while results.next().await.is_some() {
            if cancel.is_cancelled() {
                return Err(ProbeError::Stopped);
            }
        }
        self.apply_group_health();
        Ok(())
    }

    pub(super) fn apply_group_health(&self) {
        let samples = self.samples.lock().unwrap();
        for job in self.jobs.lock().unwrap().iter() {
            if let Some(index) = job.group {
                // A shared member/URL probe must retain each group's status policy.
                let expected =
                    status_ranges(&job.spec.expected_status).expect("validated health status");
                let values = job
                    .members
                    .iter()
                    .map(|name| {
                        samples.get(&(name.clone(), job.spec.url.clone())).map_or(
                            Some(u16::MAX.into()),
                            |s| {
                                (s.alive
                                    && s.status.is_some_and(|status| {
                                        expected.is_empty()
                                            || expected.iter().any(|(start, end)| {
                                                (*start..=*end).contains(&status)
                                            })
                                    }))
                                .then_some(s.delay)
                            },
                        )
                    })
                    .collect::<Vec<_>>();
                self.groups.apply_health(index, &values);
            }
        }
    }

    pub async fn tick(&self, cancel: &CancellationToken) {
        let mut work = BTreeMap::new();
        {
            let mut jobs = self.jobs.lock().unwrap();
            for job in jobs.iter_mut() {
                let urgent = job
                    .group
                    .is_some_and(|i| self.groups.selection(i).take_urgent());
                if !job.spec.enable
                    || job.spec.url.is_empty()
                    || (job.spec.interval == 0 && !urgent)
                {
                    continue;
                }
                let interval = Duration::from_secs(job.spec.interval);
                if !urgent && job.last.is_some_and(|last| last.elapsed() < interval) {
                    continue;
                }
                let active = job
                    .group
                    .map(|i| self.groups.selection(i).active(interval))
                    .unwrap_or_else(|| {
                        job.members.iter().any(|name| {
                            self.activity
                                .get(name)
                                .is_some_and(|activity| activity.active(interval))
                        }) || self
                            .groups
                            .list_states()
                            .iter()
                            .enumerate()
                            .any(|(i, group)| {
                                self.groups.selection(i).active(interval)
                                    && group.all.iter().any(|name| job.members.contains(name))
                            })
                    });
                if !urgent && job.last.is_some() && job.spec.lazy && !active {
                    job.last = Some(Instant::now());
                    continue;
                }
                job.last = Some(Instant::now());
                for member in &job.members {
                    work.entry((member.clone(), job.spec.url.clone()))
                        .or_insert_with(|| job.spec.clone());
                }
            }
        }
        let jobs = work.into_iter().map(|((name, url), spec)| async move {
            let request = DelayRequest {
                url: url.clone(),
                timeout: Duration::from_millis(if spec.timeout == 0 {
                    5000
                } else {
                    spec.timeout
                }),
                expected: status_ranges(&spec.expected_status).expect("validated health status"),
            };
            let result = self.run_probe(&name, &request, cancel).await;
            (name, url, result)
        });
        let mut results = stream::iter(jobs).buffer_unordered(10);
        while let Some((name, url, result)) = results.next().await {
            if cancel.is_cancelled() {
                return;
            }
            self.samples
                .lock()
                .unwrap()
                .insert((name, url), self.sample(&result));
        }
        self.apply_group_health();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct MemoryProbe {
        status: u16,
        peers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }
    #[async_trait::async_trait]
    impl Dispatcher for MemoryProbe {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            assert_eq!(
                session.inbound,
                crate::session::InboundKind::InternalMeasure
            );
            let (client, mut peer) = tokio::io::duplex(1024);
            let status = self.status;
            let task = tokio::spawn(async move {
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    bytes.push(peer.read_u8().await.unwrap());
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
                peer.write_all(
                    format!("HTTP/1.1 {status} Response\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            });
            self.peers.lock().unwrap().push(task);
            Ok(Box::new(client))
        }
        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }

    fn shared_status_runtime() -> (Arc<HealthRuntime>, [Arc<MemoryProbe>; 2]) {
        let config = Config::parse_yaml(
            br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.1, port: 1080}
  - {name: b, type: socks5, server: 192.0.2.2, port: 1080}
proxy-groups:
  - {name: any, type: fallback, proxies: [a,b], url: 'http://example.test/health', interval: 60, lazy: false, expected-status: '*'}
  - {name: strict, type: fallback, proxies: [a,b], url: 'http://example.test/health', interval: 60, lazy: false, expected-status: 204}
  - {name: strict-copy, type: fallback, proxies: [a,b], url: 'http://example.test/health', interval: 60, lazy: false, expected-status: 204}
"#,
        )
        .unwrap();
        let nodes = [500, 204].map(|status| {
            Arc::new(MemoryProbe {
                status,
                peers: Mutex::new(Vec::new()),
            })
        });
        let proxies: Vec<Arc<dyn Dispatcher>> = vec![nodes[0].clone(), nodes[1].clone()];
        let groups =
            ProxyGroups::new(&config.proxy_groups, proxies.clone(), nodes[1].clone()).unwrap();
        let targets = RouteTargetDispatchers::with_proxy_groups(proxies, &groups).unwrap();
        let runtime = HealthRuntime::new(
            &config,
            groups,
            targets,
            nodes[1].clone(),
            vec![],
            None,
            SecurityContext::new(),
        );
        (runtime, nodes)
    }

    fn assert_status_selections(runtime: &HealthRuntime, any: &str) {
        assert_eq!(runtime.groups.state("any").unwrap().now, any);
        assert_eq!(runtime.groups.state("strict").unwrap().now, "b");
        assert_eq!(runtime.groups.state("strict-copy").unwrap().now, "b");
    }

    async fn finish_peers(nodes: &[Arc<MemoryProbe>]) {
        for node in nodes {
            let tasks = std::mem::take(&mut *node.peers.lock().unwrap());
            for task in tasks {
                task.await.unwrap();
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shared_probes_apply_each_group_status_policy_and_refresh_failed_samples() {
        let (runtime, nodes) = shared_status_runtime();
        let cancel = CancellationToken::new();
        runtime.tick(&cancel).await;
        assert_status_selections(&runtime, "a");
        assert_eq!(runtime.samples.lock().unwrap().len(), 2);
        for node in &nodes {
            assert_eq!(node.peers.lock().unwrap().len(), 1);
        }

        runtime.tick(&cancel).await;
        for node in &nodes {
            assert_eq!(node.peers.lock().unwrap().len(), 1);
        }
        let failed = runtime.sample(&Err(ProbeError::Timeout));
        assert_eq!(failed.status, None);
        runtime.samples.lock().unwrap().insert(
            ("a".to_owned(), "http://example.test/health".to_owned()),
            failed,
        );
        runtime.apply_group_health();
        assert_status_selections(&runtime, "b");

        runtime.jobs.lock().unwrap().reverse();
        tokio::time::advance(Duration::from_secs(60)).await;
        runtime.tick(&cancel).await;
        assert_status_selections(&runtime, "a");
        assert_eq!(runtime.samples.lock().unwrap().len(), 2);
        for node in &nodes {
            assert_eq!(node.peers.lock().unwrap().len(), 2);
        }
        finish_peers(&nodes).await;
    }

    #[tokio::test(start_paused = true)]
    async fn manual_and_provider_probes_do_not_replace_group_status_policies() {
        let (runtime, nodes) = shared_status_runtime();
        let cancel = CancellationToken::new();
        runtime.tick(&cancel).await;
        let mut request = DelayRequest {
            url: "http://example.test/health".to_owned(),
            timeout: Duration::from_secs(1),
            expected: vec![(204, 204)],
        };
        runtime.node_delay("a", &request, &cancel).await.unwrap();
        assert_status_selections(&runtime, "a");
        assert!(runtime.states()["a"]["alive"].as_bool().unwrap());

        request.expected = vec![(500, 500)];
        assert_eq!(
            runtime
                .group_delay("any", &request, &cancel)
                .await
                .unwrap()
                .len(),
            2
        );
        assert_status_selections(&runtime, "a");

        let mut spec = runtime.jobs.lock().unwrap()[0].spec.clone();
        spec.expected_status = "500".to_owned();
        runtime.jobs.lock().unwrap().push(Job {
            spec,
            members: vec!["a".to_owned(), "b".to_owned()],
            group: None,
            last: None,
            provider: Some("fixture".to_owned()),
        });
        runtime
            .provider_healthcheck("fixture", &cancel)
            .await
            .unwrap();
        assert_status_selections(&runtime, "a");
        assert_eq!(runtime.samples.lock().unwrap().len(), 2);
        assert_eq!(runtime.manual_samples.lock().unwrap().len(), 2);
        finish_peers(&nodes).await;
    }

    #[tokio::test]
    async fn manual_probes_keep_one_history_per_node_and_cancel_queued_work() {
        let config = Config::parse_yaml(b"mixed-port: 1080\nrules:\n  - MATCH,DIRECT\n").unwrap();
        let direct = Arc::new(MemoryProbe {
            status: 204,
            peers: Mutex::new(Vec::new()),
        });
        let groups = ProxyGroups::new(&config.proxy_groups, vec![], direct.clone()).unwrap();
        let targets = RouteTargetDispatchers::with_proxy_groups(vec![], &groups).unwrap();
        let runtime = HealthRuntime::new(
            &config,
            groups,
            targets,
            direct.clone(),
            vec![],
            None,
            SecurityContext::new(),
        );
        let cancel = CancellationToken::new();
        for index in 0..8 {
            let request = DelayRequest {
                url: format!("http://192.0.2.1/{index}"),
                timeout: Duration::from_secs(1),
                expected: vec![(204, 204)],
            };
            assert!(
                runtime
                    .node_delay("DIRECT", &request, &cancel)
                    .await
                    .unwrap()
                    > 0
            );
        }
        assert_eq!(runtime.manual_samples.lock().unwrap().len(), 1);
        assert!(runtime.samples.lock().unwrap().is_empty());
        let mismatch = DelayRequest {
            url: "http://192.0.2.1/unexpected".into(),
            timeout: Duration::from_secs(1),
            expected: vec![(200, 200)],
        };
        assert!(
            runtime
                .node_delay("DIRECT", &mismatch, &cancel)
                .await
                .unwrap()
                > 0
        );
        {
            let samples = runtime.manual_samples.lock().unwrap();
            assert!(samples["DIRECT"].alive);
            assert_eq!(samples["DIRECT"].status, Some(204));
        }
        assert_eq!(
            runtime.states()["DIRECT"]["history"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let mut slots = Vec::new();
        for _ in 0..10 {
            slots.push(runtime.probe_slots.acquire().await.unwrap());
        }
        cancel.cancel();
        let request = DelayRequest {
            url: "http://192.0.2.1/".into(),
            timeout: Duration::from_secs(60),
            expected: vec![],
        };
        assert_eq!(
            runtime.node_delay("DIRECT", &request, &cancel).await,
            Err(ProbeError::Stopped)
        );
        drop(slots);
        let tasks = std::mem::take(&mut *direct.peers.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    }
}
