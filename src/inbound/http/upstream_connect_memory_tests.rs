// Mixed CONNECT interception and final HTTPS target exclusions use memory streams.
struct ConnectMemoryRecordingLeaf {
    origin: Arc<MemoryOrigin>,
    sessions: Arc<Mutex<Vec<StreamSession>>>,
}

#[async_trait]
impl Dispatcher for ConnectMemoryRecordingLeaf {
    fn permits_http_tcp_reuse(&self) -> bool {
        self.origin.permits_http_tcp_reuse()
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.sessions.lock().unwrap().push(session.clone());
        self.origin.connect_tcp(session).await
    }

    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

async fn connect_memory_read_response(
    client: &mut BufReader<tokio::io::DuplexStream>,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let head = framing::read_head(client, 32768).await?;
    let response = framing::ResponseHead::parse(&head)?;
    let mut body = Vec::new();
    framing::transfer_body(
        client,
        &mut body,
        response.body("GET"),
        Duration::from_secs(1),
        response.trailer_blocklist(),
        true,
    )
    .await?;
    Ok((head, body))
}

#[tokio::test]
async fn upstream_reuse_connect_http_port_intercepts_two_gets_on_one_origin_and_joins() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let leaf: Arc<dyn Dispatcher> = Arc::new(ConnectMemoryRecordingLeaf {
        origin: origin.clone(),
        sessions: sessions.clone(),
    });
    // A wrong HTTP/TUN identity fails routing on either request. The second
    // request must therefore retain CONNECT's HTTPS identity when preparing
    // its own route, as well as using the physical stream opened by the first.
    let config = crate::config::Config::parse_yaml(
        b"rules: ['IN-TYPE,HTTPS,DIRECT', 'MATCH,REJECT']\n",
    )
    .unwrap();
    let router = Arc::new(RoutingDispatcher::new(
        ProxyDispatchers::new(Vec::new()).unwrap(),
        leaf,
        None,
        RuleSet::compile(config.rules).unwrap(),
        Arc::new(EmptyGeoMatcher),
    ));
    let stats = crate::resources::RuntimeResourceStats::new("http_connect_inner_h1_memory");
    let observed = observe_sessions_with_stats(
        observe_handshakes_with_stats(router.clone(), stats.clone()),
        stats.clone(),
    );
    let context = HttpContext::new(
        Policy::compile(
            r#"targets:
  - origins: [http://203.0.113.1]
    rules:
      - response:
          headers:
            - {set: {X-Connect-Proof: intercepted}}
"#,
        )
        .unwrap(),
        observed,
        SecurityContext::new(),
    );
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(MixedEntry { context, router });
    let cancel = CancellationToken::new();
    let serving_cancel = cancel.clone();
    let (client, stream) = tokio::io::duplex(8192);
    let task = tokio::spawn(async move {
        let (read, mut write) = tokio::io::split(stream);
        let mut reader = BufReader::new(read);
        let config = HttpServerConfig::processing();
        serve_requests(
            &mut reader,
            &mut write,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:1080".parse().unwrap(),
            &dispatcher,
            &config,
            (
                Instant::now() + Duration::from_secs(10),
                &serving_cancel,
            ),
        )
        .await
    });
    let mut client = BufReader::new(client);
    // Capture all assertions until after cleanup. Even the baseline's two
    // accepts, a bad response, or a timeout must not abandon serving/peer tasks.
    let exchange = tokio::time::timeout(Duration::from_secs(3), async {
        client
            .get_mut()
            .write_all(b"CONNECT 203.0.113.1:80 HTTP/1.1\r\nHost: 203.0.113.1:80\r\n\r\n")
            .await?;
        let connect_head = framing::read_head(&mut client, 32768).await?;
        let mut responses = Vec::new();
        for path in ["one", "two"] {
            client
                .get_mut()
                .write_all(
                    format!("GET /{path} HTTP/1.1\r\nHost: 203.0.113.1\r\n\r\n").as_bytes(),
                )
                .await?;
            responses.push(connect_memory_read_response(&mut client).await?);
        }
        Ok::<_, io::Error>((connect_head, responses))
    })
    .await;
    let opened = origin.opened.load(Ordering::SeqCst);
    let active = stats.snapshot();
    let heads = origin.heads.lock().unwrap().clone();
    let bodies = origin.bodies.lock().unwrap().clone();
    let recorded_sessions = sessions.lock().unwrap().clone();

    // Keep the downstream open while Stop is joined: downstream EOF must not
    // accidentally supply the only reason the cached origin owner is released.
    cancel.cancel();
    let serving = joined(task).await;
    origin.join().await;
    drop(client);

    serving.unwrap().unwrap();
    let (connect_head, responses) = exchange.unwrap().unwrap();
    assert!(connect_head.starts_with(b"HTTP/1.1 200 Connection Established"));
    assert_eq!(opened, 1, "two inner H1 requests must share one physical accept");
    assert_eq!(heads.len(), 2, "the origin must receive both real request heads");
    assert!(heads[0].starts_with("GET /one HTTP/1.1\r\n"));
    assert!(heads[1].starts_with("GET /two HTTP/1.1\r\n"));
    assert!(heads.iter().all(|head| head.to_ascii_lowercase().contains("connection: keep-alive")));
    assert_eq!(bodies, vec![Vec::<u8>::new(), Vec::<u8>::new()]);
    assert_eq!(responses.len(), 2);
    for (head, body) in responses {
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert!(String::from_utf8(head).unwrap().to_ascii_lowercase().contains("x-connect-proof: intercepted"),
            "a raw CONNECT relay would miss the real HTTP-processing marker");
        assert_eq!(body, b"ok");
    }
    assert_eq!(recorded_sessions.len(), 1);
    assert_eq!(recorded_sessions[0].inbound, InboundKind::Https);
    assert_eq!(recorded_sessions[0].metadata.local_port, 1080);
    assert_eq!(recorded_sessions[0].destination, Destination::Ip("203.0.113.1:80".parse().unwrap()));
    assert_eq!(active.tcp_current, 1);
    assert_eq!(active.handshake_current, 0);
    assert_eq!(stats.snapshot().tcp_current, 0);
    assert_eq!(stats.snapshot().handshake_current, 0);
    assert_eq!(origin.live.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct FinalHttpsNoReuseProbe {
    prepares: AtomicUsize,
    connects: AtomicUsize,
    destinations: Mutex<Vec<Destination>>,
}

#[async_trait]
impl Dispatcher for FinalHttpsNoReuseProbe {
    fn permits_http_tcp_reuse(&self) -> bool {
        true
    }

    async fn prepare_http_tcp(
        &self,
        _: StreamSession,
    ) -> Result<Option<Box<dyn crate::dispatch::HttpTcpPlan>>, DispatchError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        Err(DispatchError::NotAllowed)
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        self.destinations.lock().unwrap().push(session.destination);
        // Deliberately stop before TLS construction or IO. No certificates,
        // private keys, socket, TLS peer, or synthetic TLS success is involved.
        Err(DispatchError::NotAllowed)
    }

    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test]
async fn upstream_reuse_final_https_target_never_prepares_a_reuse_plan_without_tls_io() {
    let probe = Arc::new(FinalHttpsNoReuseProbe::default());
    let context = HttpContext::new(
        Policy::compile(
            r#"targets:
  - origins: [http://203.0.113.1]
    rules:
      - request:
          url: {replace: https://203.0.113.1/final}
"#,
        )
        .unwrap(),
        probe.clone(),
        SecurityContext::new(),
    );
    let (client, mut stream) = tokio::io::duplex(8192);
    let task = tokio::spawn(async move {
        context
            .try_intercept(&mut stream, ingress(), CancellationToken::new())
            .await
    });
    let mut client = client;
    let exchange = tokio::time::timeout(Duration::from_secs(1), async {
        client
            .write_all(b"GET /secure HTTP/1.1\r\nHost: 203.0.113.1\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    let serving = joined(task).await;
    drop(client);

    exchange.unwrap().unwrap();
    assert!(serving.unwrap().is_err(), "the deliberate pre-TLS connect failure must remain a failure");
    assert_eq!(probe.prepares.load(Ordering::SeqCst), 0,
        "an HTTPS final target must stay out of the HTTP reuse-plan path");
    assert_eq!(probe.connects.load(Ordering::SeqCst), 1);
    assert_eq!(*probe.destinations.lock().unwrap(),
        vec![Destination::Ip("203.0.113.1:443".parse().unwrap())]);
}
