//! Transactional provider generations. Existing sessions pin their original graph.
use super::*;
use crate::config::ProxyId;
use crate::{
    config::{RuleAction, RuleKind, RuleSpec},
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    resource::{
        cache::{ProviderCache, ProviderState},
        control::{DelayRequest, DnsSnapshot, ProbeError, RuntimeResources},
    },
    routing::ProxyGroupError,
    session::{Datagram, DatagramSession, Destination, StreamSession},
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Mutex, RwLock},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};

struct Generation {
    connections: Arc<crate::connections::Registry>,
    diagnostics: Option<Arc<diagnostics::Diagnostics>>,
    health: Arc<health::HealthRuntime>,
    requirements: GeoRequirements,
    config: Config,
    dispatcher: Arc<dyn Dispatcher>,
    dns: Option<Arc<RuntimeDns>>,
    groups: Arc<ProxyGroups>,
    graph: Arc<BuiltProxyGraph>,
    targets: RouteTargetDispatchers,
    direct: Arc<dyn Dispatcher>,
}
impl Generation {
    fn from_parts(
        config: Config,
        parts: &BuiltRuntimeParts,
        requirements: GeoRequirements,
    ) -> Self {
        Self {
            connections: parts.connections.clone(),
            diagnostics: parts.diagnostics.clone(),
            health: parts.health.clone(),
            requirements,
            config,
            dispatcher: parts.dispatcher.clone(),
            dns: parts.dns.clone(),
            groups: parts.proxy_groups.clone(),
            graph: parts.proxy_graph.clone(),
            targets: parts.resource_targets.clone(),
            direct: parts.direct.clone(),
        }
    }
}
struct Refresh {
    rules: bool,
    name: String,
    reply: oneshot::Sender<Result<(), &'static str>>,
}
pub(super) struct ProviderRuntime {
    store: crate::resource::profile::SelectionStore,
    persistence_error: RwLock<Option<&'static str>>,
    current: ArcSwap<Generation>,
    retired: Mutex<Vec<Arc<Generation>>>,
    publication: Mutex<()>,
    cache: tokio::sync::Mutex<ProviderCache>,
    states: RwLock<Vec<ProviderState>>,
    requests: mpsc::Sender<Refresh>,
    receiver: tokio::sync::Mutex<Option<mpsc::Receiver<Refresh>>>,
    cancellation: CancellationToken,
    dialer: Dialer,
    limits: ResourceLimits,
    manager: Arc<GeoDataManager>,
    lease: crate::geodata::GeoDataRegistrationLease,
    geo: Arc<dyn GeoMatcher>,
}
impl ProviderRuntime {
    pub(super) fn new(
        cache: ProviderCache,
        prepared: &PreparedCore,
        parts: &BuiltRuntimeParts,
        dialer: Dialer,
    ) -> Arc<Self> {
        let (requests, receiver) = mpsc::channel(16);
        let requirements = GeoRequirements::for_rules(&prepared.config, prepared.rules.all_rules())
            .expect("prepared requirements");
        let root = prepared
            .geodata_manager
            .store_dir()
            .parent()
            .expect("dataDir");
        let store = crate::resource::profile::SelectionStore::open(
            root,
            prepared.config.profile.store_selected,
        );
        store.restore(&parts.proxy_groups);
        Arc::new(Self {
            store,
            persistence_error: RwLock::new(None),
            current: ArcSwap::from_pointee(Generation::from_parts(
                prepared.config.clone(),
                parts,
                requirements,
            )),
            retired: Mutex::new(Vec::new()),
            publication: Mutex::new(()),
            states: RwLock::new(
                cache
                    .entries
                    .iter()
                    .map(|entry| entry.state.clone())
                    .collect(),
            ),
            cache: tokio::sync::Mutex::new(cache),
            requests,
            receiver: tokio::sync::Mutex::new(Some(receiver)),
            cancellation: CancellationToken::new(),
            dialer,
            limits: prepared.limits,
            manager: prepared.geodata_manager.clone(),
            lease: prepared.geodata_registration.updater_lease(),
            geo: prepared.geodata_registration.matcher(),
        })
    }
    pub(super) fn begin_shutdown(&self) {
        self.cancellation.cancel();
        self.current.load().connections.shutdown();
        self.current.load().graph.begin_shutdown();
        for generation in self.retired.lock().unwrap().iter() {
            generation.graph.begin_shutdown();
        }
    }
    pub(super) async fn shutdown(&self) {
        self.begin_shutdown();
        let current = self.current.load_full();
        current.graph.shutdown().await;
        let retired = std::mem::take(&mut *self.retired.lock().unwrap());
        for generation in retired {
            generation.graph.shutdown().await;
        }
    }
    async fn reap(&self) {
        let expired = {
            let mut retired = self.retired.lock().unwrap();
            let mut expired = Vec::new();
            let mut i = 0;
            while i < retired.len() {
                if Arc::strong_count(&retired[i]) == 1 {
                    expired.push(retired.swap_remove(i));
                } else {
                    i += 1;
                }
            }
            expired
        };
        let changed = !expired.is_empty();
        for generation in expired {
            generation.graph.begin_shutdown();
            generation.graph.shutdown().await;
        }
        if changed && !self.cancellation.is_cancelled() {
            let current = self.current.load_full();
            if let Ok(requirements) = self.combined_requirements(&current.requirements) {
                let manager = self.manager.clone();
                let lease = self.lease.clone();
                let cancellation = self.cancellation.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    manager.replace_requirements(&lease, requirements, &cancellation)
                })
                .await;
            }
        }
    }
    fn combined_requirements(
        &self,
        next: &GeoRequirements,
    ) -> Result<GeoRequirements, &'static str> {
        let mut requirements = next.clone();
        requirements
            .extend(&self.current.load().requirements)
            .map_err(|_| "invalid resource requirements")?;
        for old in self.retired.lock().unwrap().iter() {
            requirements
                .extend(&old.requirements)
                .map_err(|_| "invalid resource requirements")?;
        }
        Ok(requirements)
    }
    pub(super) async fn run(self: Arc<Self>, parent: CancellationToken) -> io::Result<()> {
        let health = async {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {biased;
                    ()=parent.cancelled()=>{self.begin_shutdown();break;},
                    ()=self.cancellation.cancelled()=>break,
                    _=tick.tick()=>{let current=self.current.load_full(); current.health.tick(&self.cancellation).await;}
                }
            }
        };
        let worker = self.provider_loop(parent.clone());
        let (result, ()) = tokio::join!(worker, health);
        result
    }
    async fn provider_loop(self: &Arc<Self>, parent: CancellationToken) -> io::Result<()> {
        let mut receiver = self
            .receiver
            .lock()
            .await
            .take()
            .ok_or_else(|| io::Error::other("provider worker already running"))?;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                biased;
                ()=parent.cancelled()=>{self.begin_shutdown();return Ok(());}
                ()=self.cancellation.cancelled()=>return Ok(()),
                request=receiver.recv()=>if let Some(request)=request {
                    let index=self.cache.lock().await.entries.iter().position(|entry|entry.state.rule==request.rules && entry.state.name==request.name);
                    let result=match index {Some(index)=>self.update(index).await,None=>Err("unknown provider")};
                    let _=request.reply.send(result);
                },
                _=tick.tick()=>{
                    let due=self.cache.lock().await.next_due();
                    if let Some(index)=due { let _=self.update(index).await; }
                    self.reap().await;
                }
            }
        }
    }
    async fn update(self: &Arc<Self>, index: usize) -> Result<(), &'static str> {
        let mut cache = self.cache.lock().await;
        let proxy = cache.entries[index].spec.proxy.clone();
        let generation = self.current.load_full();
        let dispatcher = match self.download_dispatcher(generation.clone(), &proxy) {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                cache.reject(index);
                self.record_states(&cache);
                return Err(error);
            }
        };
        cache.entries[index].state.updating = true;
        self.record_states(&cache);
        let user_agent = generation.config.global_ua.clone();
        let etag = generation.config.etag_support;
        let candidate = cache
            .fetch(
                index,
                dispatcher,
                user_agent,
                etag,
                self.cancellation.clone(),
            )
            .await;
        self.record_states(&cache);
        let Some(candidate) = candidate.map_err(|_| "resource fetch failed")? else {
            return Ok(());
        };
        let mut contents = cache.contents.clone();
        contents.insert(cache.entries[index].key.clone(), candidate.content.clone());
        let template = cache.template.clone();
        let limits = self.limits;
        let dialer = self.dialer.clone();
        let geo = self.geo.clone();
        let previous_dns = generation.dns.clone();
        let connections = generation.connections.clone();
        let data_dir = self
            .manager
            .store_dir()
            .parent()
            .map(std::path::Path::to_path_buf);
        let expression_cancellation = self.cancellation.clone();
        let prepared = tokio::task::spawn_blocking(
            move || -> io::Result<(Config, BuiltRuntimeParts, GeoRequirements)> {
                let mut config = template
                    .materialize_with_cancel(&contents, Some(&expression_cancellation))
                    .map_err(io::Error::other)?;
                let requirements =
                    GeoRequirements::for_config(&config).map_err(io::Error::other)?;
                let rules = RuleSet::compile_config(&mut config).map_err(io::Error::other)?;
                let endpoints = vec![PreparedProxyEndpoints::default(); config.proxies.len()];
                let parts = GraphBuilder {
                    connections,
                    config: config.clone(),
                    endpoints,
                    limits,
                    rules,
                    geo_matcher: geo,
                    previous_dns,
                    data_dir,
                }
                .build(dialer)?;
                Ok((config, parts, requirements))
            },
        )
        .await
        .map_err(|_| "provider preparation failed")?;
        let (config, parts, requirements) = match prepared {
            Ok(value) => value,
            Err(_) => {
                cache.reject(index);
                self.record_states(&cache);
                return Err("provider candidate rejected");
            }
        };
        let next = Arc::new(Generation::from_parts(config, &parts, requirements.clone()));
        let requirements = self.combined_requirements(&requirements)?;
        let manager = self.manager.clone();
        let lease = self.lease.clone();
        let cancellation = self.cancellation.clone();
        let updated = tokio::task::spawn_blocking(move || {
            manager.replace_requirements(&lease, requirements, &cancellation)
        })
        .await;
        if !matches!(updated, Ok(Ok(()))) || self.cancellation.is_cancelled() {
            next.graph.begin_shutdown();
            next.graph.shutdown().await;
            return Err("provider update cancelled");
        }
        let result: io::Result<()> = {
            let _publication = self.publication.lock().unwrap();
            if self.cancellation.is_cancelled() {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                cache
                    .commit(index, candidate, &self.cancellation)
                    .map(|()| {
                        for (index, state) in self
                            .current
                            .load()
                            .groups
                            .list_states()
                            .into_iter()
                            .enumerate()
                        {
                            let forced = self
                                .current
                                .load()
                                .groups
                                .selection(index)
                                .forced()
                                .is_some();
                            let _ = next
                                .groups
                                .inherit_selection(&state.name, &state.now, forced);
                        }
                        let old = self.current.swap(next.clone());
                        self.retired.lock().unwrap().push(old);
                    })
            }
        };
        if result.is_err() {
            next.graph.begin_shutdown();
            next.graph.shutdown().await;
            cache.reject(index);
        }
        self.record_states(&cache);
        result.map_err(|_| "provider cache commit failed")
    }
    fn record_states(&self, cache: &ProviderCache) {
        *self.states.write().unwrap() = cache
            .entries
            .iter()
            .map(|entry| entry.state.clone())
            .collect();
    }
    fn download_dispatcher(
        &self,
        generation: Arc<Generation>,
        name: &str,
    ) -> Result<Arc<dyn Dispatcher>, &'static str> {
        let dispatcher = if name.is_empty() {
            generation.dispatcher.clone()
        } else {
            let action = match name {
                "DIRECT" | "COMPATIBLE" => RuleAction::Direct,
                "REJECT" => RuleAction::Reject,
                _ => {
                    if let Some(index) = generation
                        .config
                        .proxies
                        .iter()
                        .position(|proxy| proxy.tag == name)
                    {
                        RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(index).unwrap()))
                    } else if let Some(index) = generation
                        .config
                        .proxy_groups
                        .iter()
                        .position(|group| group.name == name)
                    {
                        RuleAction::Route(RouteTargetId::Group(
                            crate::config::ProxyGroupId::new(index).unwrap(),
                        ))
                    } else {
                        return Err("unknown provider download proxy");
                    }
                }
            };
            let rules = RuleSet::compile(vec![RuleSpec {
                kind: RuleKind::Match,
                action,
                no_resolve: false,
            }])
            .map_err(|_| "invalid resource route")?;
            Arc::new(RoutingDispatcher::new_with_ipv6(
                generation.targets.clone(),
                generation.direct.clone(),
                generation.dns.clone(),
                generation.config.ipv6,
                rules,
                self.geo.clone(),
            )) as Arc<dyn Dispatcher>
        };
        Ok(Arc::new(PinnedDispatcher {
            generation,
            dispatcher,
        }))
    }
}
#[async_trait]
impl RuntimeResources for ProviderRuntime {
    fn connections(&self) -> Arc<crate::connections::Registry> {
        self.current.load().connections.clone()
    }
    fn configs(&self) -> serde_json::Value {
        self.current
            .load()
            .diagnostics
            .as_ref()
            .map_or(serde_json::Value::Null, |diagnostics| diagnostics.config())
    }
    fn rules(&self) -> serde_json::Value {
        self.current.load().diagnostics.as_ref().map_or_else(
            || serde_json::json!({"rules": []}),
            |diagnostics| diagnostics.rules(),
        )
    }

    fn groups(&self) -> Arc<ProxyGroups> {
        self.current.load().groups.clone()
    }
    fn select(&self, group: &str, member: &str) -> Result<(), ProxyGroupError> {
        let _publication = self.publication.lock().unwrap();
        self.current.load().groups.select(group, member)?;
        *self.persistence_error.write().unwrap() = self
            .store
            .save(group, member)
            .err()
            .map(|_| "selection cache write failed");
        Ok(())
    }
    fn health(&self) -> serde_json::Value {
        serde_json::json!({"proxies":self.current.load().health.states(),"selectionError":*self.persistence_error.read().unwrap()})
    }
    fn providers(&self, rules: bool) -> serde_json::Value {
        let providers = self
            .states
            .read()
            .unwrap()
            .iter()
            .filter(|state| state.rule == rules)
            .map(|state| {
                let mut value = serde_json::to_value(state).expect("provider status");
                value["type"] = serde_json::json!(if rules { "Rule" } else { "Proxy" });
                if !rules {
                    let current = self.current.load_full();
                    let health = current.health.states();
                    value["proxies"] = serde_json::json!(
                        current
                            .config
                            .provider_members
                            .get(&state.name)
                            .into_iter()
                            .flatten()
                            .filter_map(|name| health.get(name))
                            .collect::<Vec<_>>()
                    );
                }
                (state.name.clone(), value)
            })
            .collect::<BTreeMap<_, _>>();
        serde_json::json!({"providers":providers})
    }
    fn dns(&self) -> Option<DnsSnapshot> {
        let generation = self.current.load_full();
        generation.dns.clone().map(|dns| DnsSnapshot {
            dns,
            _generation: Some(generation),
        })
    }
    async fn node_delay(
        &self,
        name: &str,
        request: &DelayRequest,
        cancel: &CancellationToken,
    ) -> Result<u64, ProbeError> {
        let generation = self.current.load_full();
        tokio::select! { biased;
            () = self.cancellation.cancelled() => Err(ProbeError::Stopped),
            result = generation.health.node_delay(name, request, cancel) => result,
        }
    }
    async fn group_delay(
        &self,
        name: &str,
        request: &DelayRequest,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<String, u64>, ProbeError> {
        let generation = {
            // Reset and persist under the same publication lock as manual selection.
            // Release it before any probe waits or network I/O.
            let _publication = self.publication.lock().unwrap();
            let generation = self.current.load_full();
            if let Ok(state) = generation.groups.state(name)
                && matches!(
                    state.kind,
                    crate::config::GroupKind::UrlTest | crate::config::GroupKind::Fallback
                )
            {
                if let Some(index) = generation
                    .config
                    .proxy_groups
                    .iter()
                    .position(|group| group.name == name)
                {
                    generation.groups.selection(index).clear_forced();
                }
                *self.persistence_error.write().unwrap() = self
                    .store
                    .save(name, "")
                    .err()
                    .map(|_| "selection cache write failed");
            }
            generation
        };
        tokio::select! { biased;
            () = self.cancellation.cancelled() => Err(ProbeError::Stopped),
            result = generation.health.group_delay(name, request, cancel) => result,
        }
    }
    async fn provider_healthcheck(
        &self,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let generation = self.current.load_full();
        tokio::select! { biased;
            () = self.cancellation.cancelled() => Err(ProbeError::Stopped),
            result = generation.health.provider_healthcheck(name, cancel) => result,
        }
    }
    async fn refresh(&self, rules: bool, name: &str) -> Result<(), &'static str> {
        if self.cancellation.is_cancelled() {
            return Err("runtime stopped");
        }
        let (reply, response) = oneshot::channel();
        tokio::select! {biased; ()=self.cancellation.cancelled()=>Err("runtime stopped"),result=async {self.requests.send(Refresh{rules,name:name.to_owned(),reply}).await.map_err(|_|"runtime stopped")?;response.await.map_err(|_|"runtime stopped")?}=>result}
    }
}
#[async_trait]
impl Dispatcher for ProviderRuntime {
    fn supports_udp(&self) -> bool {
        self.current.load().dispatcher.supports_udp()
    }

    async fn sniff_plan(
        &self,
        source: SocketAddr,
        destination: &Destination,
    ) -> Option<crate::sniffing::Plan> {
        if self.cancellation.is_cancelled() {
            return None;
        }
        self.current
            .load_full()
            .dispatcher
            .sniff_plan(source, destination)
            .await
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        if self.cancellation.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        let generation = self.current.load_full();
        let io = generation.dispatcher.connect_tcp(session).await?;
        Ok(Box::new(GenerationStream {
            io,
            _generation: generation,
        }))
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if self.cancellation.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        let generation = self.current.load_full();
        let io = generation.dispatcher.open_datagram(session).await?;
        Ok(Box::new(GenerationDatagram {
            io,
            _generation: generation,
        }))
    }
}
struct PinnedDispatcher {
    generation: Arc<Generation>,
    dispatcher: Arc<dyn Dispatcher>,
}
#[async_trait]
impl Dispatcher for PinnedDispatcher {
    fn supports_udp(&self) -> bool {
        self.dispatcher.supports_udp()
    }

    async fn sniff_plan(
        &self,
        source: SocketAddr,
        destination: &Destination,
    ) -> Option<crate::sniffing::Plan> {
        self.dispatcher.sniff_plan(source, destination).await
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let io = self.dispatcher.connect_tcp(session).await?;
        Ok(Box::new(GenerationStream {
            io,
            _generation: self.generation.clone(),
        }))
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let io = self.dispatcher.open_datagram(session).await?;
        Ok(Box::new(GenerationDatagram {
            io,
            _generation: self.generation.clone(),
        }))
    }
}
struct GenerationStream {
    io: BoxStream,
    _generation: Arc<Generation>,
}
impl AsyncRead for GenerationStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for GenerationStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
struct GenerationDatagram {
    io: Box<dyn DatagramTransport>,
    _generation: Arc<Generation>,
}
#[async_trait]
impl DatagramTransport for GenerationDatagram {
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.io.payload_budget(peer)
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.io.send(datagram).await
    }
    async fn send_with_flow_id(
        &mut self,
        datagram: Datagram,
        id: &[u8],
    ) -> Result<(), DispatchError> {
        self.io.send_with_flow_id(datagram, id).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.io.receive().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.io.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::SystemResolver;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn file_refresh_publishes_valid_members_and_preserves_old_sessions() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("nodes.yaml");
        let payload = |name: &str| {
            format!("proxies: [{{name: {name}, type: socks5, server: 192.0.2.1, port: 1080}}]\n")
        };
        std::fs::write(&file, payload("old")).unwrap();
        let config = Config::parse_yaml(
            br#"
mixed-port: 1080
proxy-providers:
  remote: {type: file, path: nodes.yaml, filter: '(?=.)'}
proxy-groups:
  - {name: choice, type: select, use: [remote]}
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [192.0.2.53]
profile: {store-fake-ip: true}
rules: ['MATCH,choice']
"#,
        )
        .unwrap();
        let manager =
            GeoDataManager::open(&root.path().join("geodata"), Duration::from_secs(86400)).unwrap();
        let prepared = PreparedCore::prepare_config(
            config,
            manager,
            &SystemResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
        let live = parts.resources.clone().unwrap();
        let generation = live.current.load_full();
        let query = crate::dns::build_query(1, "example.com", crate::dns::QueryType::A).unwrap();
        let wire = generation
            .dns
            .as_ref()
            .unwrap()
            .exchange(&query)
            .await
            .unwrap();
        assert!(
            !crate::dns::parse_response(&wire)
                .unwrap()
                .answers
                .is_empty()
        );
        let registry = live.connections();
        let weak = Arc::downgrade(&generation);
        let (io, mut peer) = tokio::io::duplex(32);
        let mut old_session = GenerationStream {
            io: Box::new(io),
            _generation: generation,
        };
        assert_eq!(live.groups().state("choice").unwrap().now, "old");
        std::fs::write(&file, payload("new-node")).unwrap();
        live.update(0).await.unwrap();
        assert_eq!(live.groups().state("choice").unwrap().now, "new-node");
        assert!(Arc::ptr_eq(&registry, &live.connections()));
        peer.write_all(b"active").await.unwrap();
        let mut buffer = [0; 6];
        old_session.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"active");
        live.reap().await;
        assert!(weak.upgrade().is_some());
        std::fs::write(
            &file,
            b"proxies: [{name: bad, type: socks5, server: missing}]\n",
        )
        .unwrap();
        assert!(live.update(0).await.is_err());
        assert_eq!(live.groups().state("choice").unwrap().now, "new-node");
        assert!(live.providers(false)["providers"]["remote"]["error"].is_string());
        std::fs::write(&file, payload(&"x".repeat(4097))).unwrap();
        assert!(live.update(0).await.is_err());
        assert_eq!(live.groups().state("choice").unwrap().now, "new-node");
        drop(old_session);
        live.reap().await;
        assert!(weak.upgrade().is_none());
        let worker = tokio::spawn(live.clone().run(CancellationToken::new()));
        live.begin_shutdown();
        worker.await.unwrap().unwrap();
        live.shutdown().await;
        assert!(live.refresh(false, "remote").await.is_err());
    }
}
