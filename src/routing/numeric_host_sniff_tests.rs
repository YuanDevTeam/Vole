mod numeric_host_sniff_tests {
    use super::*;

    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: observed.example\r\n\r\n";

    fn router(settings: &str, dns: Option<Arc<dyn RoutingDns>>) -> RoutingDispatcher {
        let config = crate::config::Config::parse_yaml(settings.as_bytes()).unwrap();
        dispatcher(
            Arc::new(RecordingDispatcher::default()),
            Arc::new(RecordingDispatcher::default()),
            dns,
            Vec::new(),
        )
        .with_sniffer(&config.sniffer)
    }

    async fn observe(
        router: &RoutingDispatcher,
        destination: Destination,
        expected_active: bool,
    ) {
        let mut session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Socks5,
            source: "198.51.100.2:9000".parse().unwrap(),
            destination: destination.clone(),
            sniffed_domain: None,
        };
        let plan = router
            .sniff_plan(session.source, &session.destination)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plan.tcp_enabled(), expected_active, "{destination:?}");
        // Reading a plan must not rewrite the caller's ingress metadata.
        assert_eq!(session.destination, destination);
        assert!(session.metadata.original.is_none());

        let mut unread = REQUEST;
        let prefix = plan.sniff(&mut unread, &mut session).await.unwrap();
        assert_eq!([prefix.as_slice(), unread].concat(), REQUEST);
        assert_eq!(
            session.sniffed_domain.as_deref(),
            expected_active.then_some("observed.example")
        );
        // All fixtures use override=false. Even accepted sniffing must retain
        // the original Domain wire target and the snapshot must describe it.
        assert_eq!(session.destination, destination);
        assert_eq!(
            session.metadata.original.as_ref().unwrap().destination,
            destination
        );
        if !expected_active {
            assert!(prefix.is_empty());
            assert_eq!(unread, REQUEST);
        }
    }

    #[tokio::test]
    async fn numeric_host_sniff_plan_matches_ip_for_pure_ip_and_exclusions() {
        for (literal, extra, expected) in [
            ("203.0.113.7", "", true),
            ("2001:db8::7", "", true),
            ("203.0.113.7", "  parse-pure-ip: false\n", false),
            (
                "203.0.113.7",
                "  skip-dst-address: [203.0.113.0/24]\n",
                false,
            ),
            (
                "2001:db8::7",
                "  skip-dst-address: ['2001:db8::/32']\n",
                false,
            ),
            (
                "203.0.113.7",
                "  skip-src-address: [198.51.100.0/24]\n",
                false,
            ),
        ] {
            let settings = format!(
                "sniffer:\n  enable: true\n  override-destination: false\n{extra}  sniff:\n    HTTP: {{ports: [80]}}\n"
            );
            let router = router(&settings, None);
            let ip: IpAddr = literal.parse().unwrap();
            let domain = Destination::domain(literal, 80).unwrap();
            let address = Destination::Ip(SocketAddr::new(ip, 80));
            observe(&router, domain, expected).await;
            observe(&router, address, expected).await;
        }
    }

    struct NumericDns {
        fake: Option<&'static str>,
        hint: Option<&'static str>,
        fake_lookups: AtomicUsize,
        hint_lookups: AtomicUsize,
    }

    #[async_trait]
    impl RoutingDns for NumericDns {
        fn recover_fake_ip(&self, address: IpAddr) -> Result<Option<String>, DispatchError> {
            assert_eq!(address, "203.0.113.7".parse::<IpAddr>().unwrap());
            self.fake_lookups.fetch_add(1, Ordering::Relaxed);
            Ok(self.fake.map(str::to_owned))
        }

        async fn domain_hint(&self, address: IpAddr) -> Option<String> {
            assert_eq!(address, "203.0.113.7".parse::<IpAddr>().unwrap());
            self.hint_lookups.fetch_add(1, Ordering::Relaxed);
            self.hint.map(str::to_owned)
        }

        async fn resolve(&self, _: &str) -> Result<Vec<IpAddr>, DispatchError> {
            panic!("sniff admission must not resolve a numeric host")
        }

        async fn exchange(&self, _: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            panic!("sniff admission must not exchange DNS packets")
        }
    }

    #[tokio::test]
    async fn numeric_host_sniff_plan_reuses_dns_mapping_and_fake_ip_admission() {
        for (fake, hint, extra, expected) in [
            (None, Some("mapped.example"), "", true),
            (
                None,
                Some("mapped.example"),
                "  force-dns-mapping: false\n",
                false,
            ),
            (Some("fake.example"), None, "", false),
            (
                Some("fake.example"),
                None,
                "  force-domain: [fake.example]\n",
                true,
            ),
        ] {
            let settings = format!(
                "sniffer:\n  enable: true\n  parse-pure-ip: false\n  override-destination: false\n{extra}  sniff:\n    HTTP: {{ports: [80]}}\n"
            );
            let dns = Arc::new(NumericDns {
                fake,
                hint,
                fake_lookups: AtomicUsize::new(0),
                hint_lookups: AtomicUsize::new(0),
            });
            let router = router(&settings, Some(dns.clone()));
            observe(
                &router,
                Destination::domain("203.0.113.7", 80).unwrap(),
                expected,
            )
            .await;
            observe(
                &router,
                Destination::Ip("203.0.113.7:80".parse().unwrap()),
                expected,
            )
            .await;
            assert_eq!(dns.fake_lookups.load(Ordering::Relaxed), 2);
            assert_eq!(
                dns.hint_lookups.load(Ordering::Relaxed),
                if fake.is_some() { 0 } else { 2 }
            );
        }
    }
}
