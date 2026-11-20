#[cfg(all(feature = "inbound-http", feature = "outbound-http"))]
mod http_reuse_memory_tests {
    use super::*;
    use crate::{
        dialer::{Dialer, ResolvedEndpoint},
        dispatch::{HttpTcpPlan, HttpTcpReuseKey},
        outbound::{ConnectorDispatcher, DirectOutbound, UpstreamPath, http::HttpOutbound},
        security::SecurityContext,
        session::InboundMetadata,
    };
    use std::collections::BTreeMap;

    const PROXY: &str = "192.0.2.10:8080";

    // No test opens a plan. The real protocol and routing objects below only
    // prepare immutable equality evidence; their endpoints are never dialled.
    struct OpaqueNoIo;

    #[async_trait]
    impl Dispatcher for OpaqueNoIo {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            panic!("HTTP reuse preparation must not connect an opaque dispatcher")
        }

        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            panic!("HTTP reuse preparation must not open a datagram transport")
        }
    }

    struct NoBusinessDns;

    #[async_trait]
    impl RoutingDns for NoBusinessDns {
        async fn resolve(&self, _: &str) -> Result<Vec<IpAddr>, DispatchError> {
            panic!("proxy preparation must not resolve the symbolic business destination")
        }

        async fn exchange(&self, _: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            panic!("HTTP reuse preparation must not exchange DNS packets")
        }

        async fn domain_hint(&self, _: IpAddr) -> Option<String> {
            None
        }
    }

    fn business_session() -> StreamSession {
        StreamSession {
            metadata: InboundMetadata {
                local_port: 1080,
                user: Some(Arc::from("memory-user-a")),
                local_address: Some("198.51.100.1:1080".parse().unwrap()),
                original: None,
            },
            inbound: InboundKind::Http,
            source: "198.51.100.2:20000".parse().unwrap(),
            destination: Destination::domain("business.invalid", 443).unwrap(),
            sniffed_domain: None,
        }
    }

    fn proxy_endpoint() -> ResolvedEndpoint {
        let address: SocketAddr = PROXY.parse().unwrap();
        ResolvedEndpoint {
            logical_host: address.ip().to_string(),
            port: address.port(),
            addresses: vec![address],
        }
    }

    fn http_node(upstream: UpstreamPath) -> Arc<dyn Dispatcher> {
        let address: SocketAddr = PROXY.parse().unwrap();
        let config = crate::config::HttpOutboundConfig {
            address: address.ip().to_string(),
            port: address.port(),
            tls: None,
            auth: None,
            headers: BTreeMap::new(),
        };
        Arc::new(ConnectorDispatcher::new(Arc::new(
            HttpOutbound::with_shared_security(
                &config,
                upstream,
                &SecurityContext::new(),
                1,
                32 * 1024,
            )
            .unwrap(),
        )))
    }

    fn static_http_node() -> Arc<dyn Dispatcher> {
        http_node(UpstreamPath::direct(proxy_endpoint(), Dialer::default()))
    }

    fn memory_router(
        nodes: Vec<Arc<dyn Dispatcher>>,
        direct: Arc<dyn Dispatcher>,
        rules: Vec<RuleSpec>,
    ) -> RoutingDispatcher {
        let mut router = RoutingDispatcher::new(
            ProxyDispatchers::new(nodes).unwrap(),
            direct,
            None,
            RuleSet::compile(rules).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        router.dns = Some(Arc::new(NoBusinessDns));
        router
    }

    fn proxy_router(node: Arc<dyn Dispatcher>) -> RoutingDispatcher {
        memory_router(
            vec![node],
            Arc::new(OpaqueNoIo),
            vec![rule(RuleKind::Match, proxy_action(0))],
        )
    }

    fn group_router(
        nodes: Vec<Arc<dyn Dispatcher>>,
        configs: Vec<SelectProxyGroupConfig>,
    ) -> (RoutingDispatcher, Arc<ProxyGroups>) {
        let direct: Arc<dyn Dispatcher> = Arc::new(OpaqueNoIo);
        let groups = ProxyGroups::new(&configs, nodes.clone(), direct.clone()).unwrap();
        let mut router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct,
            None,
            RuleSet::compile(vec![rule(RuleKind::Match, group_action(0))]).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        router.dns = Some(Arc::new(NoBusinessDns));
        (router, groups)
    }

    fn node_member(index: usize) -> ProxyGroupMemberTarget {
        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(ProxyId::new(index).unwrap()))
    }

    fn group_member(index: usize) -> ProxyGroupMemberTarget {
        ProxyGroupMemberTarget::Route(RouteTargetId::Group(ProxyGroupId::new(index).unwrap()))
    }

    async fn plan(router: &RoutingDispatcher, session: StreamSession) -> Box<dyn HttpTcpPlan> {
        router
            .prepare_http_tcp(session)
            .await
            .expect("route preparation must succeed without IO")
            .expect("ordinary business TCP must return an owned plan")
    }

    fn key(plan: &dyn HttpTcpPlan) -> HttpTcpReuseKey {
        plan.reuse_key()
            .expect("a proven static HTTP proxy must provide equality evidence")
            .clone()
    }

    #[tokio::test]
    async fn immutable_proxy_preparation_repeats_without_resolving_business_domain() {
        for upstream in [
            UpstreamPath::direct(proxy_endpoint(), Dialer::default()),
            UpstreamPath::LazyDirect {
                dialer: Dialer::default(),
            },
        ] {
            let router = proxy_router(http_node(upstream));
            let session = business_session();
            let (decision, _) = router.prepare_tcp_route(&session).await.unwrap();
            assert_eq!(decision.destination, session.destination);
            assert!(decision.resolved_addresses.is_none());

            let first = plan(&router, session.clone()).await;
            let second = plan(&router, session.clone()).await;
            let cloned_router = router.clone_parts();
            let cloned = plan(&cloned_router, session).await;
            assert!(key(first.as_ref()).same(&key(second.as_ref())));
            assert!(key(first.as_ref()).same(&key(cloned.as_ref())));
        }
    }

    #[tokio::test]
    async fn immutable_proxy_keys_preserve_every_session_identity_dimension() {
        let router = proxy_router(static_http_node());
        let original = business_session();
        let baseline = key(plan(&router, original.clone()).await.as_ref());
        let mut variants = Vec::new();

        let mut changed = original.clone();
        changed.metadata.user = Some(Arc::from("memory-user-b"));
        variants.push(("authenticated account", changed));

        let mut changed = original.clone();
        changed.source.set_port(20001);
        variants.push(("source connection", changed));

        let mut changed = original.clone();
        changed.source.set_ip("198.51.100.3".parse().unwrap());
        variants.push(("source address", changed));

        let mut changed = original.clone();
        changed.metadata.local_port = 1081;
        variants.push(("listener port", changed));

        let mut changed = original.clone();
        changed.metadata.local_address = Some("198.51.100.4:1080".parse().unwrap());
        variants.push(("accepted local address", changed));

        let mut changed = original.clone();
        changed.inbound = InboundKind::Socks5;
        variants.push(("inbound kind", changed));

        let mut changed = original.clone();
        changed.destination = Destination::domain("other-business.invalid", 443).unwrap();
        variants.push(("authority hostname", changed));

        let mut changed = original.clone();
        changed.destination = Destination::domain("business.invalid", 8443).unwrap();
        variants.push(("authority port", changed));

        let mut changed = original.clone();
        changed.sniffed_domain = Some("observed-business.invalid".into());
        variants.push(("sniffed routing metadata", changed));

        let mut changed = original;
        changed.capture_original();
        Arc::make_mut(changed.metadata.original.as_mut().unwrap()).destination =
            Destination::domain("original-business.invalid", 443).unwrap();
        variants.push(("original ingress snapshot", changed));

        for (dimension, session) in variants {
            let changed = key(plan(&router, session).await.as_ref());
            assert!(
                !baseline.same(&changed),
                "changed {dimension} must not borrow the previous upstream"
            );
        }
    }

    #[tokio::test]
    async fn immutable_proxy_keys_keep_rule_and_leaf_generations_distinct() {
        let node = static_http_node();
        let router = proxy_router(node.clone());
        let baseline = key(plan(&router, business_session()).await.as_ref());

        // Identical text and the same concrete leaf do not merge generations.
        let replacement_rules = proxy_router(node);
        let replacement = key(plan(&replacement_rules, business_session()).await.as_ref());
        assert!(!baseline.same(&replacement));

        // Keep this router's exact rules/session while replacing the concrete
        // protocol owner with an independently configured equivalent node.
        let mut replacement_leaf = router.clone_parts();
        replacement_leaf.route_targets = ProxyDispatchers::new(vec![static_http_node()]).unwrap();
        let replacement = key(plan(&replacement_leaf, business_session()).await.as_ref());
        assert!(!baseline.same(&replacement));
    }

    #[tokio::test]
    async fn immutable_proxy_group_selection_invalidates_the_old_leaf_key() {
        let (router, groups) = group_router(
            vec![static_http_node(), static_http_node()],
            vec![select_group(
                "choice",
                vec![("first", node_member(0)), ("second", node_member(1))],
            )],
        );
        let first = key(plan(&router, business_session()).await.as_ref());
        let repeat = key(plan(&router, business_session()).await.as_ref());
        assert!(first.same(&repeat));

        groups.select("choice", "second").unwrap();
        let second = key(plan(&router, business_session()).await.as_ref());
        assert!(!first.same(&second));
        assert!(first.same(&repeat), "previous evidence remains immutable");
        let repeat_second = key(plan(&router, business_session()).await.as_ref());
        assert!(second.same(&repeat_second));
    }

    #[tokio::test]
    async fn immutable_proxy_group_chain_changes_even_when_the_leaf_is_identical() {
        let (router, groups) = group_router(
            vec![static_http_node()],
            vec![
                select_group(
                    "entry",
                    vec![("left", group_member(1)), ("right", group_member(2))],
                ),
                select_group("left", vec![("same-leaf", node_member(0))]),
                select_group("right", vec![("same-leaf", node_member(0))]),
            ],
        );
        let session = business_session();
        let (_, left) = router.prepare_tcp_route(&session).await.unwrap();
        let left = left.unwrap();
        let first = key(plan(&router, session.clone()).await.as_ref());

        groups.select("entry", "right").unwrap();
        let (_, right) = router.prepare_tcp_route(&session).await.unwrap();
        let right = right.unwrap();
        assert!(Arc::ptr_eq(&left.dispatcher, &right.dispatcher));
        assert_ne!(left.chain, right.chain);
        let second = key(plan(&router, session).await.as_ref());
        assert!(!first.same(&second));
    }

    #[tokio::test]
    async fn opaque_and_nonstatic_proxy_paths_never_produce_reuse_keys() {
        let opaque = proxy_router(Arc::new(OpaqueNoIo));
        assert!(plan(&opaque, business_session()).await.reuse_key().is_none());

        let bound = http_node(UpstreamPath::direct(
            proxy_endpoint(),
            Dialer::default().with_source_ip("192.0.2.44".parse().unwrap()),
        ));
        let bound = proxy_router(bound);
        assert!(plan(&bound, business_session()).await.reuse_key().is_none());

        let mut mismatched = proxy_endpoint();
        mismatched.addresses = vec!["192.0.2.11:8080".parse().unwrap()];
        let mismatched = proxy_router(http_node(UpstreamPath::direct(
            mismatched,
            Dialer::default(),
        )));
        assert!(
            plan(&mismatched, business_session())
                .await
                .reuse_key()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejected_routes_keep_their_decision_and_have_no_reuse_key() {
        let router = memory_router(
            vec![static_http_node()],
            Arc::new(DirectOutbound::new(Dialer::default())),
            vec![rule(RuleKind::Match, RuleAction::Reject)],
        );
        let mut session = business_session();
        session.destination = Destination::Ip("203.0.113.10:443".parse().unwrap());
        let (decision, selected) = router.prepare_tcp_route(&session).await.unwrap();
        assert_eq!(decision.action, RuleAction::Reject);
        assert!(selected.is_none());
        assert!(plan(&router, session).await.reuse_key().is_none());

        let (router, _) = group_router(
            vec![static_http_node()],
            vec![select_group(
                "rejecting",
                vec![("REJECT", ProxyGroupMemberTarget::Reject)],
            )],
        );
        let session = business_session();
        let (decision, selected) = router.prepare_tcp_route(&session).await.unwrap();
        assert_eq!(decision.action, group_action(0));
        let selected = selected.unwrap();
        assert!(!selected.direct);
        assert_eq!(selected.chain, vec!["REJECT", "rejecting"]);
        assert!(plan(&router, session).await.reuse_key().is_none());
    }

    #[tokio::test]
    async fn direct_reuse_still_rejects_opaque_or_bound_physical_egress() {
        for direct in [
            Arc::new(OpaqueNoIo) as Arc<dyn Dispatcher>,
            Arc::new(DirectOutbound::new(
                Dialer::default().with_source_ip("192.0.2.44".parse().unwrap()),
            )),
        ] {
            let router = memory_router(
                Vec::new(),
                direct,
                vec![rule(RuleKind::Match, RuleAction::Direct)],
            );
            let mut session = business_session();
            session.destination = Destination::Ip("203.0.113.10:443".parse().unwrap());
            assert!(plan(&router, session).await.reuse_key().is_none());
        }
    }

    struct MemoryDirectDns;

    #[async_trait]
    impl RoutingDns for MemoryDirectDns {
        async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            assert_eq!(host, "business.invalid");
            Ok(vec![
                "203.0.113.10".parse().unwrap(),
                "203.0.113.11".parse().unwrap(),
            ])
        }

        async fn exchange(&self, _: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            panic!("memory-only address selection must not exchange DNS packets")
        }

        async fn domain_hint(&self, _: IpAddr) -> Option<String> {
            None
        }
    }

    #[tokio::test]
    async fn direct_concurrent_address_racing_still_has_no_reuse_key() {
        let mut router = memory_router(
            Vec::new(),
            Arc::new(DirectOutbound::new(Dialer::default())),
            vec![rule(RuleKind::Match, RuleAction::Direct)],
        );
        router.dns = Some(Arc::new(MemoryDirectDns));
        let concurrent = router.clone_parts().with_tcp_concurrent(true);
        assert!(
            plan(&concurrent, business_session())
                .await
                .reuse_key()
                .is_none()
        );
        assert!(plan(&router, business_session()).await.reuse_key().is_some());
    }
}
