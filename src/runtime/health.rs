//! Shared probe scheduling and automatic group selection for one resource generation.
use super::*;
use crate::{
    config::{HealthCheckConfig, status_ranges},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    resource::probe::{self, Target},
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
}
struct Job {
    spec: HealthCheckConfig,
    members: Vec<String>,
    group: Option<usize>,
    last: Option<Instant>,
}
pub(super) struct HealthRuntime {
    jobs: Mutex<Vec<Job>>,
    samples: Mutex<BTreeMap<(String, String), Sample>>,
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
            jobs: Mutex::new(jobs),
            samples: Mutex::new(BTreeMap::new()),
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
        for ((name, _), sample) in samples.iter() {
            nodes.insert(name.clone(),serde_json::json!({"name":name,"alive":sample.alive,"history":[{"time":sample.time,"delay":sample.delay}]}));
        }
        serde_json::json!(nodes)
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
            let action = match name.as_str() {
                "DIRECT" | "COMPATIBLE" => Some(crate::config::RuleAction::Direct),
                "REJECT" => Some(crate::config::RuleAction::Reject),
                _ => self
                    .names
                    .get(&name)
                    .copied()
                    .map(crate::config::RuleAction::Route),
            };
            let dispatcher = action.map(|action| {
                let rules = RuleSet::compile(vec![crate::config::RuleSpec {
                    kind: crate::config::RuleKind::Match,
                    action,
                    no_resolve: false,
                }])
                .expect("health route");
                Arc::new(RoutingDispatcher::new_with_ipv6(
                    self.targets.clone(),
                    self.direct.clone(),
                    self.dns.clone(),
                    self.ipv6,
                    rules,
                    Arc::new(crate::routing::EmptyGeoMatcher),
                )) as Arc<dyn Dispatcher>
            });
            let result = async {
                let target = Target::parse(&url)?;
                let expected = status_ranges(&spec.expected_status).map_err(io::Error::other)?;
                probe::probe(
                    &target,
                    dispatcher.ok_or_else(|| io::Error::other("unavailable health target"))?,
                    Duration::from_millis(if spec.timeout == 0 {
                        5000
                    } else {
                        spec.timeout
                    }),
                    self.unified,
                    &expected,
                    cancel,
                )
                .await
            }
            .await;
            (name, url, result)
        });
        let mut results = stream::iter(jobs).buffer_unordered(10);
        while let Some((name, url, result)) = results.next().await {
            if cancel.is_cancelled() {
                return;
            }
            self.samples.lock().unwrap().insert(
                (name, url),
                Sample {
                    alive: result.is_ok(),
                    delay: result.unwrap_or(0),
                    time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                },
            );
        }
        let samples = self.samples.lock().unwrap();
        for job in self.jobs.lock().unwrap().iter() {
            if let Some(index) = job.group {
                let values = job
                    .members
                    .iter()
                    .map(|name| {
                        samples
                            .get(&(name.clone(), job.spec.url.clone()))
                            .map_or(Some(u16::MAX.into()), |s| s.alive.then_some(s.delay))
                    })
                    .collect::<Vec<_>>();
                self.groups.apply_health(index, &values);
            }
        }
    }
}
