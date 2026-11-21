//! Configured routing hints in the real HTTP adapter, using only memory peers.
use super::*;
use crate::{
    config::Config,
    routing::{GeoMatcher, RoutingContext},
};
use std::net::{IpAddr, SocketAddr};

struct ExampleGeo;
impl GeoMatcher for ExampleGeo {
    fn matches_geosite(&self, code: &str, domain: &str) -> bool {
        code == "cn" && domain == "allowed.example"
    }
    fn matches_geoip(&self, _: &str, _: IpAddr) -> bool {
        false
    }
}

struct SniffingOrigin {
    origin: Arc<Origin>,
    policy: Arc<crate::sniffing::Policy>,
}
#[async_trait]
impl Dispatcher for SniffingOrigin {
    async fn sniff_plan(
        &self,
        source: SocketAddr,
        destination: &Destination,
    ) -> Result<Option<crate::sniffing::Plan>, DispatchError> {
        let host = match destination {
            Destination::Domain { host, .. } => Some(host.as_str()),
            Destination::Ip(_) => None,
        };
        Ok(Some(self.policy.plan(source, destination, host, false)?))
    }
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.origin.connect_tcp(session).await
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.origin.open_datagram(session).await
    }
}

const NATIVE_HEADER: &str = r#"targets:
  - origins: [http://allowed.example, http://203.0.113.1]
    rules:
      - response:
          headers:
            - {set: {X-Native: kept}}
"#;
const MAIN: &str = "sniffer:\n  enable: true\n  parse-pure-ip: true\n  override-destination: false\n  sniff:\n    HTTP: {ports: [80]}\nrules: ['GEOSITE,cn,DIRECT','MATCH,REJECT']\n";

async fn exchange(main: &str, http: &str, host: &str) -> (String, StreamSession) {
    let config = Config::parse_yaml(main.as_bytes()).unwrap();
    let origin = Arc::new(Origin::default());
    let dispatcher = Arc::new(SniffingOrigin {
        origin: origin.clone(),
        policy: crate::sniffing::Policy::new(Arc::new(config.sniffer), Arc::new(ExampleGeo)),
    });
    let context = HttpContext::new(
        Policy::compile(http).unwrap(),
        dispatcher,
        SecurityContext::new(),
    );
    let (mut client, mut server) = tokio::io::duplex(8192);
    let mut initial = session();
    initial.sniffed_domain = None;
    let task = tokio::spawn(async move {
        assert!(matches!(
            context
                .try_intercept(&mut server, initial, CancellationToken::new())
                .await
                .unwrap(),
            Intercept::Handled
        ));
    });
    client
        .write_all(
            format!("GET /original HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    origin.join().await;
    let selected = origin.sessions.lock().unwrap();
    assert_eq!(selected.len(), 1);
    (response, selected[0].clone())
}

#[tokio::test]
async fn plain_h1_preserves_configured_geosite_hint_and_selected_ip() {
    let (response, selected) = exchange(MAIN, NATIVE_HEADER, "allowed.example").await;
    assert!(response.to_ascii_lowercase().contains("x-native: kept\r\n"));
    assert_eq!(selected.destination, session().destination);
    assert_eq!(selected.sniffed_domain.as_deref(), Some("allowed.example"));
    let main = Config::parse_yaml(MAIN.as_bytes()).unwrap();
    let routing = RoutingContext::with_domain_hint(
        crate::config::Network::Tcp,
        &selected.destination,
        selected.sniffed_domain.as_deref(),
    )
    .unwrap();
    assert!(crate::routing::matches_rule(&main.rules[0], &routing, &ExampleGeo).unwrap());
    assert_eq!(
        selected.metadata.original.as_ref().unwrap().destination,
        session().destination
    );
}

#[tokio::test]
async fn plain_h1_does_not_enable_excluded_or_unconfigured_http_sniffing() {
    let configurations = [
        MAIN.replace("enable: true", "enable: false"),
        MAIN.replace("parse-pure-ip: true", "parse-pure-ip: false"),
        MAIN.replace("ports: [80]", "ports: [8080]"),
        MAIN.replace("HTTP:", "TLS:"),
        MAIN.replace("  sniff:", "  skip-domain: [allowed.example]\n  sniff:"),
        MAIN.replace("  sniff:", "  skip-src-address: [198.18.0.0/16]\n  sniff:"),
        MAIN.replace("  sniff:", "  skip-dst-address: [203.0.113.0/24]\n  sniff:"),
    ];
    for main in configurations {
        let (_, selected) = exchange(&main, NATIVE_HEADER, "allowed.example").await;
        assert_eq!(selected.destination, session().destination, "{main}");
        assert_eq!(selected.sniffed_domain, None, "{main}");
    }
    let (_, selected) = exchange(MAIN, NATIVE_HEADER, "203.0.113.1").await;
    assert_eq!(selected.sniffed_domain, None);
}

#[tokio::test]
async fn plain_h1_honors_explicit_override_and_discards_old_hint_on_origin_change() {
    let main = MAIN.replace("override-destination: false", "override-destination: true");
    let (_, selected) = exchange(&main, NATIVE_HEADER, "allowed.example").await;
    assert_eq!(
        selected.destination,
        Destination::domain("allowed.example", 80).unwrap()
    );
    assert_eq!(selected.sniffed_domain.as_deref(), Some("allowed.example"));
    assert_eq!(
        selected.metadata.original.as_ref().unwrap().destination,
        session().destination
    );
    let (_, selected) = exchange(
        MAIN,
        r#"targets:
  - origins: [http://allowed.example]
    rules:
      - request:
          url: {replace: {value: http://final.example/, mode: match}}
"#,
        "allowed.example",
    )
    .await;
    assert_eq!(
        selected.destination,
        Destination::domain("final.example", 80).unwrap()
    );
    assert_eq!(selected.sniffed_domain, None);
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn request_script_sees_the_sniffed_base_then_final_origin_replaces_its_hint() {
    let (_, selected) = exchange(
        MAIN,
        r#"targets:
  - origins: [http://allowed.example]
    rules:
      - name: final-target
        request:
          js:
            source: 'function rewrite(input) { return {type:"modify",url:"http://script-final.example/"}; }'
"#,
        "allowed.example",
    )
    .await;
    assert_eq!(
        selected.destination,
        Destination::domain("script-final.example", 80).unwrap()
    );
    assert_eq!(selected.sniffed_domain, None);
}
