use super::GroupSelection;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, atomic::Ordering},
};

use async_trait::async_trait;

use crate::{
    config::{ProxyGroupId, ProxyGroupMemberTarget, RouteTargetId, SelectProxyGroupConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{Datagram, DatagramSession, StreamSession},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyGroupState {
    pub kind: crate::config::GroupKind,
    pub(crate) name: String,
    pub(crate) all: Vec<String>,
    pub(crate) now: String,
    pub(crate) hidden: bool,
    pub(crate) icon: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyGroupError {
    UnknownGroup,
    UnknownMember,
}

impl fmt::Display for ProxyGroupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownGroup => "unknown proxy group",
            Self::UnknownMember => "unknown proxy group member",
        })
    }
}

impl std::error::Error for ProxyGroupError {}

struct SelectProxyGroup {
    config: SelectProxyGroupConfig,
    name: String,
    members: Box<[ProxyGroupMember]>,
    selected: Arc<GroupSelection>,
    disable_udp: bool,
    hidden: bool,
    icon: String,
}

struct ProxyGroupMember {
    name: String,
    target: ProxyGroupMemberTarget,
}

pub(crate) struct ResolvedProxyGroupLeaf {
    pub(crate) dispatcher: Arc<dyn Dispatcher>,
    pub(crate) direct: bool,
}

/// Immutable select-group graph with one atomically replaceable member index
/// per group. Concrete node dispatchers and DIRECT are shared with the rest of
/// the runtime; groups own no protocol resources or background tasks.
pub(crate) struct ProxyGroups {
    proxies: Box<[Arc<dyn Dispatcher>]>,
    direct: Arc<dyn Dispatcher>,
    reject: Arc<dyn Dispatcher>,
    groups: Box<[SelectProxyGroup]>,
    ids_by_name: HashMap<String, ProxyGroupId>,
}

impl fmt::Debug for ProxyGroups {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyGroups")
            .field("proxies", &self.proxies.len())
            .field("groups", &self.groups.len())
            .finish_non_exhaustive()
    }
}

impl ProxyGroups {
    #[cfg(test)]
    pub(crate) fn new(
        configs: &[SelectProxyGroupConfig],
        proxies: Vec<Arc<dyn Dispatcher>>,
        direct: Arc<dyn Dispatcher>,
    ) -> Result<Arc<Self>, DispatchError> {
        let selections = configs
            .iter()
            .map(|config| Arc::new(GroupSelection::new(config.initial_member)))
            .collect::<Vec<_>>();
        Self::with_selections(configs, proxies, direct, &selections)
    }

    pub(crate) fn with_selections(
        configs: &[SelectProxyGroupConfig],
        proxies: Vec<Arc<dyn Dispatcher>>,
        direct: Arc<dyn Dispatcher>,
        selections: &[Arc<GroupSelection>],
    ) -> Result<Arc<Self>, DispatchError> {
        if selections.len() != configs.len() {
            return Err(DispatchError::Other(
                "proxy group selection registry length mismatch".to_owned(),
            ));
        }
        let mut ids_by_name = HashMap::with_capacity(configs.len());
        for (index, config) in configs.iter().enumerate() {
            if config.members.is_empty() || config.initial_member >= config.members.len() {
                return Err(DispatchError::Other(format!(
                    "proxy group {index} has invalid members or initial selection"
                )));
            }
            if ids_by_name
                .insert(
                    config.name.clone(),
                    ProxyGroupId::new(index).expect("ProxyGroupId has no count-based ceiling"),
                )
                .is_some()
            {
                return Err(DispatchError::Other(format!(
                    "duplicate proxy group at index {index}"
                )));
            }
            for member in &config.members {
                match member.target {
                    ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(id))
                        if id.index() >= proxies.len() =>
                    {
                        return Err(DispatchError::Other(format!(
                            "proxy group {index} references unknown proxy id {}",
                            id.index()
                        )));
                    }
                    ProxyGroupMemberTarget::Route(RouteTargetId::Group(id))
                        if id.index() >= configs.len() =>
                    {
                        return Err(DispatchError::Other(format!(
                            "proxy group {index} references unknown group id {}",
                            id.index()
                        )));
                    }
                    _ => {}
                }
            }
        }

        Ok(Arc::new(Self {
            proxies: proxies.into_boxed_slice(),
            direct,
            reject: Arc::new(RejectDispatcher),
            groups: configs
                .iter()
                .zip(selections)
                .map(|(config, selection)| {
                    selection.configure(config.max_failed_times, config.health.timeout);
                    SelectProxyGroup {
                        config: config.clone(),
                        name: config.name.clone(),
                        members: config
                            .members
                            .iter()
                            .map(|member| ProxyGroupMember {
                                name: member.name.clone(),
                                target: member.target,
                            })
                            .collect(),
                        selected: selection.clone(),
                        disable_udp: config.disable_udp,
                        hidden: config.hidden,
                        icon: config.icon.clone(),
                    }
                })
                .collect(),
            ids_by_name,
        }))
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn list_states(&self) -> Vec<ProxyGroupState> {
        self.groups.iter().map(SelectProxyGroup::state).collect()
    }

    pub(crate) fn state(&self, group: &str) -> Result<ProxyGroupState, ProxyGroupError> {
        let id = self
            .ids_by_name
            .get(group)
            .copied()
            .ok_or(ProxyGroupError::UnknownGroup)?;
        Ok(self.groups[id.index()].state())
    }

    pub(crate) fn select(&self, group: &str, member: &str) -> Result<(), ProxyGroupError> {
        self.inherit_selection(group, member, true)
    }
    pub(crate) fn inherit_selection(
        &self,
        group: &str,
        member: &str,
        forced: bool,
    ) -> Result<(), ProxyGroupError> {
        let id = self
            .ids_by_name
            .get(group)
            .copied()
            .ok_or(ProxyGroupError::UnknownGroup)?;
        let group = &self.groups[id.index()];
        let selected = group
            .members
            .iter()
            .position(|candidate| candidate.name == member)
            .ok_or(ProxyGroupError::UnknownMember)?;
        if forced {
            group.selected.force(selected);
        } else {
            group.selected.store(selected, Ordering::Release);
        }
        Ok(())
    }

    pub(crate) fn resolve_leaf(
        &self,
        group_id: ProxyGroupId,
    ) -> Result<ResolvedProxyGroupLeaf, DispatchError> {
        self.resolve_leaf_for(group_id, false)
    }

    fn resolve_leaf_for(
        &self,
        mut group_id: ProxyGroupId,
        udp: bool,
    ) -> Result<ResolvedProxyGroupLeaf, DispatchError> {
        for _ in 0..=self.groups.len() {
            let group = self.groups.get(group_id.index()).ok_or_else(|| {
                DispatchError::Other(format!("unknown proxy group id {}", group_id.index()))
            })?;
            if udp && group.disable_udp {
                return Err(DispatchError::NotAllowed);
            }
            group.selected.touch();
            let selected = group.selected.load(Ordering::Acquire);
            let member = group.members.get(selected).ok_or_else(|| {
                DispatchError::Other(format!(
                    "proxy group {} has invalid selected index {selected}",
                    group_id.index()
                ))
            })?;
            match member.target {
                ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(id)) => {
                    return self
                        .proxies
                        .get(id.index())
                        .cloned()
                        .map(|dispatcher| ResolvedProxyGroupLeaf {
                            dispatcher,
                            direct: false,
                        })
                        .ok_or_else(|| {
                            DispatchError::Other(format!("unknown proxy id {}", id.index()))
                        });
                }
                ProxyGroupMemberTarget::Route(RouteTargetId::Group(id)) => group_id = id,
                ProxyGroupMemberTarget::Direct => {
                    return Ok(ResolvedProxyGroupLeaf {
                        dispatcher: self.direct.clone(),
                        direct: true,
                    });
                }
                ProxyGroupMemberTarget::Reject => {
                    return Ok(ResolvedProxyGroupLeaf {
                        dispatcher: self.reject.clone(),
                        direct: false,
                    });
                }
            }
        }
        Err(DispatchError::Other(
            "proxy group nesting exceeded the runtime hop ceiling".to_owned(),
        ))
    }

    pub(crate) fn selection(&self, index: usize) -> Arc<GroupSelection> {
        self.groups[index].selected.clone()
    }
    pub(crate) fn apply_health(&self, index: usize, samples: &[Option<u64>]) {
        let group = &self.groups[index];
        if group.config.kind == crate::config::GroupKind::Select
            || samples.len() != group.members.len()
        {
            return;
        }
        if let Some(forced) = group.selected.forced() {
            if samples[forced].is_some() {
                group.selected.store(forced, Ordering::Release);
                return;
            }
            group.selected.clear_forced();
        }
        let old = group.selected.load(Ordering::Acquire);
        let next = if group.config.kind == crate::config::GroupKind::Fallback {
            samples.iter().position(Option::is_some).unwrap_or(0)
        } else {
            let fastest = samples
                .iter()
                .enumerate()
                .filter_map(|(i, d)| d.map(|d| (i, d)))
                .min_by_key(|(_, d)| *d)
                .map(|(i, _)| i)
                .unwrap_or(0);
            if samples[old]
                .zip(samples[fastest])
                .is_some_and(|(a, b)| a <= b.saturating_add(u64::from(group.config.tolerance)))
            {
                old
            } else {
                fastest
            }
        };
        group.selected.store(next, Ordering::Release);
    }

    pub(super) fn dispatcher(self: &Arc<Self>, id: ProxyGroupId) -> Arc<dyn Dispatcher> {
        Arc::new(SelectProxyGroupDispatcher {
            groups: self.clone(),
            id,
        })
    }
}

impl SelectProxyGroup {
    fn state(&self) -> ProxyGroupState {
        let selected = self.selected.load(Ordering::Acquire);
        ProxyGroupState {
            kind: self.config.kind,
            name: self.name.clone(),
            all: self
                .members
                .iter()
                .map(|member| member.name.clone())
                .collect(),
            now: self.members[selected].name.clone(),
            hidden: self.hidden,
            icon: self.icon.clone(),
        }
    }
}

struct SelectProxyGroupDispatcher {
    groups: Arc<ProxyGroups>,
    id: ProxyGroupId,
}

#[async_trait]
impl Dispatcher for SelectProxyGroupDispatcher {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let leaf = self.groups.resolve_leaf(self.id)?;
        let result = leaf.dispatcher.connect_tcp(session).await;
        if !leaf.direct && !matches!(result, Err(DispatchError::NotAllowed)) {
            self.groups.groups[self.id.index()]
                .selected
                .outcome(result.is_ok());
        }
        result
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.groups
            .resolve_leaf_for(self.id, true)?
            .dispatcher
            .open_datagram(session)
            .await
    }
}

struct RejectDispatcher;

#[async_trait]
impl Dispatcher for RejectDispatcher {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(RejectDatagramTransport))
    }
}

struct RejectDatagramTransport;

#[async_trait]
impl DatagramTransport for RejectDatagramTransport {
    async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::atomic::Ordering, time::Duration};

    use bytes::Bytes;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{
        config::{ProxyGroupMemberConfig, ProxyId},
        session::{Destination, InboundKind},
    };

    #[derive(Default)]
    struct RecordingDispatcher {
        tcp_calls: AtomicUsize,
        udp_opens: AtomicUsize,
        udp_sends: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Dispatcher for RecordingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_calls.fetch_add(1, Ordering::Relaxed);
            let (client, _server) = tokio::io::duplex(1);
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_opens.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(RecordingDatagramTransport {
                sends: self.udp_sends.clone(),
            }))
        }
    }

    struct RecordingDatagramTransport {
        sends: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DatagramTransport for RecordingDatagramTransport {
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }

    struct GatedDispatcher {
        calls: AtomicUsize,
        started: Semaphore,
        release: Semaphore,
    }

    struct FailingDispatcher;

    #[async_trait]
    impl Dispatcher for FailingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::HostUnreachable)
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NetworkUnreachable)
        }
    }

    impl GatedDispatcher {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                started: Semaphore::new(0),
                release: Semaphore::new(0),
            }
        }
    }

    #[async_trait]
    impl Dispatcher for GatedDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.started.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            let (client, _server) = tokio::io::duplex(1);
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            unreachable!()
        }
    }

    fn member(name: &str, target: ProxyGroupMemberTarget) -> ProxyGroupMemberConfig {
        ProxyGroupMemberConfig {
            name: name.to_owned(),
            target,
        }
    }

    fn group(
        name: &str,
        members: Vec<ProxyGroupMemberConfig>,
        initial_member: usize,
    ) -> SelectProxyGroupConfig {
        SelectProxyGroupConfig {
            kind: crate::config::GroupKind::Select,
            health: crate::config::HealthCheckConfig::default(),
            tolerance: 0,
            max_failed_times: 5,
            disable_udp: false,
            hidden: false,
            icon: String::new(),
            name: name.to_owned(),
            members,
            initial_member,
        }
    }

    fn stream_session() -> StreamSession {
        StreamSession {
            inbound: InboundKind::Http,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::Ip("192.0.2.1:443".parse().unwrap()),
            sniffed_domain: None,
        }
    }

    fn datagram_session() -> DatagramSession {
        DatagramSession::new(InboundKind::Http, "127.0.0.1:10000".parse().unwrap())
    }

    fn datagram() -> Datagram {
        Datagram {
            remote: Destination::Ip("192.0.2.1:443".parse::<SocketAddr>().unwrap()),
            payload: Bytes::from_static(b"payload"),
            sniffed_domain: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_groups_apply_tolerance_recover_and_restore_selection() {
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.1, port: 1080}
  - {name: b, type: socks5, server: 192.0.2.2, port: 1080}
proxy-groups:
  - {name: fastest, type: url-test, proxies: [a,b], tolerance: 20, max-failed-times: 2}
  - {name: backup, type: fallback, proxies: [a,b]}
  - {name: manual, type: select, proxies: [a,b], default-selected: a}
"#,
        )
        .unwrap();
        let node = Arc::new(FailingDispatcher);
        let groups = ProxyGroups::new(
            &config.proxy_groups,
            vec![node.clone(), node.clone()],
            node.clone(),
        )
        .unwrap();
        groups.apply_health(0, &[Some(100), Some(90)]);
        assert_eq!(groups.state("fastest").unwrap().now, "a");
        groups.apply_health(0, &[Some(100), Some(60)]);
        assert_eq!(groups.state("fastest").unwrap().now, "b");
        groups.apply_health(1, &[None, Some(60)]);
        assert_eq!(groups.state("backup").unwrap().now, "b");
        groups.apply_health(1, &[Some(100), Some(60)]);
        assert_eq!(groups.state("backup").unwrap().now, "a");
        groups.select("fastest", "a").unwrap();
        groups.apply_health(0, &[None, Some(60)]);
        assert_eq!(groups.state("fastest").unwrap().now, "b");
        let selection = groups.selection(0);
        selection.outcome(false);
        selection.outcome(false);
        assert!(selection.take_urgent());
        tokio::time::advance(std::time::Duration::from_secs(301)).await;
        assert!(!selection.active(std::time::Duration::from_secs(300)));
        let root = tempfile::tempdir().unwrap();
        let store = crate::resource::profile::SelectionStore::open(root.path(), true);
        groups.select("manual", "b").unwrap();
        store.save("manual", "b").unwrap();
        let restarted =
            ProxyGroups::new(&config.proxy_groups, vec![node.clone(), node.clone()], node).unwrap();
        crate::resource::profile::SelectionStore::open(root.path(), true).restore(&restarted);
        assert_eq!(restarted.state("manual").unwrap().now, "b");
    }

    #[tokio::test]
    async fn nested_selection_preserves_duplicates_and_snapshots_new_transports() {
        let first = Arc::new(RecordingDispatcher::default());
        let second = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let configs = [
            group(
                "child",
                vec![
                    member(
                        "first",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    ),
                    member(
                        "first",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    ),
                    member(
                        "second",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(1).unwrap(),
                        )),
                    ),
                ],
                2,
            ),
            group(
                "parent",
                vec![
                    member(
                        "child",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Group(
                            ProxyGroupId::new(0).unwrap(),
                        )),
                    ),
                    member("DIRECT", ProxyGroupMemberTarget::Direct),
                    member("REJECT", ProxyGroupMemberTarget::Reject),
                ],
                0,
            ),
        ];
        let groups = ProxyGroups::new(
            &configs,
            vec![first.clone(), second.clone()],
            direct.clone(),
        )
        .unwrap();
        let parent = groups.dispatcher(ProxyGroupId::new(1).unwrap());

        assert_eq!(
            groups.list_states(),
            vec![
                ProxyGroupState {
                    kind: crate::config::GroupKind::Select,
                    name: "child".to_owned(),
                    all: vec!["first".to_owned(), "first".to_owned(), "second".to_owned()],
                    now: "second".to_owned(),
                    hidden: false,
                    icon: String::new(),
                },
                ProxyGroupState {
                    kind: crate::config::GroupKind::Select,
                    name: "parent".to_owned(),
                    all: vec!["child".to_owned(), "DIRECT".to_owned(), "REJECT".to_owned()],
                    now: "child".to_owned(),
                    hidden: false,
                    icon: String::new(),
                },
            ]
        );
        assert_eq!(
            groups.select("missing", "first"),
            Err(ProxyGroupError::UnknownGroup)
        );
        assert_eq!(
            groups.select("child", "missing"),
            Err(ProxyGroupError::UnknownMember)
        );
        assert_eq!(groups.state("child").unwrap().now, "second");

        let mut old_udp = parent.open_datagram(datagram_session()).await.unwrap();
        groups.select("child", "first").unwrap();
        assert_eq!(
            groups.groups[0].selected.load(Ordering::Acquire),
            0,
            "duplicate selection must resolve to the first matching member"
        );
        old_udp.send(datagram()).await.unwrap();
        let mut new_udp = parent.open_datagram(datagram_session()).await.unwrap();
        new_udp.send(datagram()).await.unwrap();

        assert_eq!(second.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(second.udp_sends.load(Ordering::Relaxed), 1);
        assert_eq!(first.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(first.udp_sends.load(Ordering::Relaxed), 1);

        groups.select("parent", "DIRECT").unwrap();
        parent.connect_tcp(stream_session()).await.unwrap();
        assert_eq!(direct.tcp_calls.load(Ordering::Relaxed), 1);

        groups.select("parent", "REJECT").unwrap();
        assert!(matches!(
            parent.connect_tcp(stream_session()).await,
            Err(DispatchError::NotAllowed)
        ));
        let mut rejected = parent.open_datagram(datagram_session()).await.unwrap();
        rejected.send(datagram()).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), rejected.receive())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn in_flight_tcp_keeps_the_leaf_selected_before_await() {
        let old = Arc::new(GatedDispatcher::new());
        let new = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let groups = ProxyGroups::new(
            &[group(
                "group",
                vec![
                    member(
                        "old",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    ),
                    member(
                        "new",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(1).unwrap(),
                        )),
                    ),
                ],
                0,
            )],
            vec![old.clone(), new.clone()],
            direct,
        )
        .unwrap();
        let dispatcher = groups.dispatcher(ProxyGroupId::new(0).unwrap());
        let pending = tokio::spawn({
            let dispatcher = dispatcher.clone();
            async move { dispatcher.connect_tcp(stream_session()).await }
        });
        old.started.acquire().await.unwrap().forget();

        groups.select("group", "new").unwrap();
        old.release.add_permits(1);
        pending.await.unwrap().unwrap();
        dispatcher.connect_tcp(stream_session()).await.unwrap();

        assert_eq!(old.calls.load(Ordering::Relaxed), 1);
        assert_eq!(new.tcp_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn selected_member_failure_does_not_fallback_or_change_selection() {
        let fallback = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let groups = ProxyGroups::new(
            &[group(
                "group",
                vec![
                    member(
                        "failing",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    ),
                    member(
                        "fallback",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(1).unwrap(),
                        )),
                    ),
                ],
                0,
            )],
            vec![Arc::new(FailingDispatcher), fallback.clone()],
            direct,
        )
        .unwrap();
        let dispatcher = groups.dispatcher(ProxyGroupId::new(0).unwrap());

        assert!(matches!(
            dispatcher.connect_tcp(stream_session()).await,
            Err(DispatchError::HostUnreachable)
        ));
        assert!(matches!(
            dispatcher.open_datagram(datagram_session()).await,
            Err(DispatchError::NetworkUnreachable)
        ));
        assert_eq!(fallback.tcp_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fallback.udp_opens.load(Ordering::Relaxed), 0);
        assert_eq!(groups.state("group").unwrap().now, "failing");
    }

    #[test]
    fn unexpected_group_cycle_hits_the_iterative_hop_ceiling() {
        let direct = Arc::new(RecordingDispatcher::default());
        let groups = ProxyGroups::new(
            &[
                group(
                    "a",
                    vec![member(
                        "b",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Group(
                            ProxyGroupId::new(1).unwrap(),
                        )),
                    )],
                    0,
                ),
                group(
                    "b",
                    vec![member(
                        "a",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Group(
                            ProxyGroupId::new(0).unwrap(),
                        )),
                    )],
                    0,
                ),
            ],
            Vec::new(),
            direct,
        )
        .unwrap();

        let error = match groups.resolve_leaf(ProxyGroupId::new(0).unwrap()) {
            Ok(_) => panic!("unexpected cycle resolved"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("hop ceiling"));
    }
}
