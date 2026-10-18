//! Shared inbound sniffing policy. Configuration and GeoData are retained, not snapshots.
use crate::{
    config::{Network, RuleKind, RuleSpec, SnifferConfig},
    routing::{GeoMatcher, RoutingContext},
    session::Destination,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub(crate) struct Policy {
    pub(crate) config: Arc<SnifferConfig>,
    geo: Arc<dyn GeoMatcher>,
    force: crate::dns::fake_ip::DomainFilter,
    skip: crate::dns::fake_ip::DomainFilter,
}
impl Policy {
    pub(crate) fn new(config: Arc<SnifferConfig>, geo: Arc<dyn GeoMatcher>) -> Arc<Self> {
        Arc::new(Self {
            force: crate::dns::fake_ip::DomainFilter::new(&config.force_domain),
            skip: crate::dns::fake_ip::DomainFilter::new(&config.skip_domain),
            config,
            geo,
        })
    }
    pub(crate) fn plan(
        self: &Arc<Self>,
        source: SocketAddr,
        destination: &Destination,
        host: Option<&str>,
        mapped: bool,
    ) -> Result<Plan, crate::config::MatchFailure> {
        let decision = crate::config::RuleDecision::default();
        let snapshot = self.geo.routing_snapshot();
        let geo = snapshot.as_deref().unwrap_or(self.geo.as_ref());
        let blocked = address_matches(&self.config.skip_src_address, source.ip(), geo, &decision)?
            || match destination {
                Destination::Ip(address) => {
                    address_matches(&self.config.skip_dst_address, address.ip(), geo, &decision)?
                }
                _ => false,
            };
        let active = self.config.enable
            && !blocked
            && ((host.is_none() && self.config.parse_pure_ip)
                || (mapped && self.config.force_dns_mapping)
                || match host {
                    Some(host) => self.force.matches(host, geo, &decision)?,
                    None => false,
                });
        Ok(Plan {
            policy: self.clone(),
            port: destination.port(),
            active,
            decision,
        })
    }
}
fn address_matches(
    rules: &[RuleSpec],
    ip: IpAddr,
    geo: &dyn GeoMatcher,
    decision: &crate::config::RuleDecision,
) -> Result<bool, crate::config::MatchFailure> {
    decision.visit()?;
    let destination = Destination::Ip(SocketAddr::new(ip, 1));
    let context = RoutingContext::new(Network::Tcp, &destination)
        .expect("literal destination")
        .with_decision(decision);
    for rule in rules {
        let matched = if let RuleKind::RuleSet {
            content: Some(set), ..
        } = &rule.kind
        {
            set.matches_ip(ip, geo, decision)?
        } else {
            match crate::routing::matches_rule(rule, &context, geo) {
                Ok(matched) => matched,
                Err(
                    crate::routing::PredicateFailure::NeedsIpResolution
                    | crate::routing::PredicateFailure::NeedsProcessLookup,
                ) => false,
                Err(crate::routing::PredicateFailure::Evaluation(failure)) => return Err(failure),
            }
        };
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Per-request decision shared by the inbound adapters. A disabled plan performs no reads.
#[derive(Clone)]
pub struct Plan {
    policy: Arc<Policy>,
    port: u16,
    active: bool,
    decision: crate::config::RuleDecision,
}
impl Plan {
    #[cfg(feature = "tun")]
    pub(crate) fn with_cancellation(
        self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Self {
        self.decision.set_cancellation(cancellation);
        self
    }
    #[cfg(any(feature = "tun", test))]
    pub(crate) fn standalone(config: Arc<SnifferConfig>, port: u16) -> Self {
        Self {
            active: config.enable,
            decision: Default::default(),
            port,
            policy: Policy::new(config, Arc::new(crate::routing::EmptyGeoMatcher)),
        }
    }
    pub(crate) fn accepts(&self, host: &str) -> Result<bool, crate::config::MatchFailure> {
        let snapshot = self.policy.geo.routing_snapshot();
        Ok(!self.policy.skip.matches(
            host,
            snapshot.as_deref().unwrap_or(self.policy.geo.as_ref()),
            &self.decision,
        )?)
    }
    pub(crate) fn tcp_enabled(&self) -> bool {
        self.active
            && (self.policy.config.matches_http_port(self.port)
                || self.policy.config.matches_tls_port(self.port))
    }
    pub(crate) fn quic_enabled(&self) -> bool {
        self.active && self.policy.config.matches_quic_port(self.port)
    }
    pub(crate) async fn sniff<R: tokio::io::AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        session: &mut crate::session::StreamSession,
    ) -> Result<Vec<u8>, crate::config::MatchFailure> {
        session.capture_original();
        self.decision.check()?;
        if !self.tcp_enabled() {
            return Ok(Vec::new());
        }
        use crate::tcp_sniffer::{SniffOutcome, SniffProtocol, TcpSniffer};
        let protocols = [
            (
                SniffProtocol::Tls,
                self.policy.config.matches_tls_port(self.port),
            ),
            (
                SniffProtocol::Http,
                self.policy.config.matches_http_port(self.port),
            ),
        ]
        .into_iter()
        .filter_map(|(protocol, enabled)| enabled.then_some(protocol))
        .collect();
        let mut sniffer = TcpSniffer::with_protocols(protocols);
        if let Ok(SniffOutcome::Matched { protocol, domain }) = sniffer.sniff(reader).await
            && self.accepts(&domain)?
        {
            let override_destination = match protocol {
                SniffProtocol::Http => self.policy.config.http_override,
                SniffProtocol::Tls => self.policy.config.tls_override,
            };
            if override_destination {
                session.destination = Destination::Domain {
                    host: domain.clone(),
                    port: self.port,
                };
            }
            session.sniffed_domain = Some(domain);
        }
        Ok(sniffer.into_buffered())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        session::{InboundKind, StreamSession},
    };
    fn policy() -> Arc<Policy> {
        let config = Config::parse_yaml(
            br#"
mixed-port: 1080
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: false
  force-domain: ['+.force.example']
  skip-domain: ['+.skip.example']
  skip-src-address: [192.0.2.0/24]
  skip-dst-address: [203.0.113.0/24]
  override-destination: false
  sniff:
    HTTP:
      ports: [443]
    TLS:
      ports: [443]
      override-destination: true
"#,
        )
        .unwrap();
        Policy::new(
            Arc::new(config.sniffer),
            Arc::new(crate::routing::EmptyGeoMatcher),
        )
    }
    #[test]
    fn sniff_policy_distinguishes_mapping_forcing_and_exclusions() {
        let policy = policy();
        let source = "198.51.100.1:8000".parse().unwrap();
        let destination = Destination::Ip("198.51.100.2:443".parse().unwrap());
        assert!(
            !policy
                .plan(source, &destination, None, false)
                .unwrap()
                .tcp_enabled()
        );
        assert!(
            policy
                .plan(source, &destination, Some("mapped.example"), true)
                .unwrap()
                .tcp_enabled()
        );
        assert!(
            !policy
                .plan(source, &destination, Some("fake.example"), false)
                .unwrap()
                .tcp_enabled()
        );
        assert!(
            policy
                .plan(source, &destination, Some("api.force.example"), false)
                .unwrap()
                .tcp_enabled()
        );
        assert!(
            !policy
                .plan(
                    "192.0.2.2:99".parse().unwrap(),
                    &destination,
                    Some("api.force.example"),
                    true
                )
                .unwrap()
                .tcp_enabled()
        );
        assert!(
            !policy
                .plan(
                    source,
                    &Destination::Ip("203.0.113.1:443".parse().unwrap()),
                    Some("api.force.example"),
                    true
                )
                .unwrap()
                .tcp_enabled()
        );
    }
    #[tokio::test]
    async fn sniff_shared_prefix_selects_protocol_override_and_replays_every_byte() {
        let policy = policy();
        let destination = Destination::Ip("198.51.100.2:443".parse().unwrap());
        let source = "198.51.100.1:8000".parse().unwrap();
        let plan = policy
            .plan(source, &destination, Some("api.force.example"), false)
            .unwrap();
        for (mut input, host, overridden) in [
            (
                b"GET / HTTP/1.1\r\nHost: http.example\r\n\r\n".to_vec(),
                Some("http.example"),
                false,
            ),
            (
                crate::tcp_sniffer::tests::tls_client_hello("tls.example"),
                Some("tls.example"),
                true,
            ),
            (
                crate::tcp_sniffer::tests::tls_client_hello("api.skip.example"),
                None,
                false,
            ),
        ] {
            input.extend_from_slice(b"business-bytes");
            let mut reader = input.as_slice();
            let mut session = StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Tun,
                source,
                destination: destination.clone(),
                sniffed_domain: None,
            };
            let prefix = plan.sniff(&mut reader, &mut session).await.unwrap();
            assert_eq!([prefix.as_slice(), reader].concat(), input);
            assert_eq!(session.sniffed_domain.as_deref(), host);
            if overridden {
                assert_eq!(
                    session.destination,
                    Destination::Domain {
                        host: host.unwrap().into(),
                        port: 443
                    }
                );
            } else {
                assert_eq!(session.destination, destination);
            }
        }
    }
}
