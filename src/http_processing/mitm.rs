//! Selective business TLS termination. Trust installation belongs to the host.
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, io};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RawMitm {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default, deserialize_with = "non_null_vec")]
    pub(crate) domains: Vec<RawDomain>,
    #[serde(default, deserialize_with = "non_null_vec")]
    pub(crate) exclude_domains: Vec<RawDomain>,
    #[serde(default = "default_ports", deserialize_with = "non_null_vec")]
    pub(crate) ports: Vec<u16>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RawDomain {
    pub(crate) pattern: String,
    #[serde(default = "enabled")]
    pub(crate) enabled: bool,
}

fn enabled() -> bool {
    true
}

fn non_null_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("MITM sequence must not be null"))
}
fn default_ports() -> Vec<u16> {
    vec![443]
}

impl Default for RawMitm {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            exclude_domains: Vec::new(),
            ports: default_ports(),
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid selective TLS policy")
}

struct Pattern {
    name: Box<str>,
    suffix: bool,
}

impl Pattern {
    fn compile(raw: &str) -> io::Result<Self> {
        let (suffix, raw) = raw.strip_prefix("*.").map_or((false, raw), |s| (true, s));
        if raw.contains('*') || raw.len() > 253 || raw.parse::<std::net::IpAddr>().is_ok() {
            return Err(invalid());
        }
        let name = crate::routing::normalize_domain_name(raw).map_err(|_| invalid())?;
        if !matches!(
            rustls::pki_types::ServerName::try_from(name.as_str()),
            Ok(rustls::pki_types::ServerName::DnsName(_))
        ) {
            return Err(invalid());
        }
        Ok(Self {
            name: name.into(),
            suffix,
        })
    }

    fn matches(&self, name: &str) -> bool {
        if self.suffix {
            name.strip_suffix(self.name.as_ref())
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
        } else {
            name == self.name.as_ref()
        }
    }
}

fn patterns(raw: &[RawDomain]) -> io::Result<Box<[Pattern]>> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(raw.len());
    for entry in raw {
        let pattern = Pattern::compile(&entry.pattern)?;
        if !seen.insert((pattern.name.clone(), pattern.suffix)) {
            return Err(invalid());
        }
        if entry.enabled {
            output.push(pattern);
        }
    }
    Ok(output.into())
}

impl RawMitm {
    pub(crate) fn validate_static(&self) -> io::Result<()> {
        if self.domains.len() > 64
            || self.exclude_domains.len() > 64
            || self.ports.len() > 64
            || self.ports.contains(&0)
        {
            return Err(invalid());
        }
        let domains = patterns(&self.domains)?;
        patterns(&self.exclude_domains)?;
        if self.enabled && (domains.is_empty() || self.ports.is_empty()) {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(feature = "inbound-http")]
mod enabled {
    use super::super::{HttpContext, Intercept, Scheme, authority::Authority, io::Replay};
    use super::{Pattern, RawMitm, invalid, patterns};
    use crate::{
        http_processing::private_context::CaMaterial,
        session::StreamSession,
        tcp_sniffer::{SniffOutcome, SniffProtocol, TcpSniffer},
    };
    use std::{io, sync::Arc, time::Duration};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_util::sync::CancellationToken;
    use url::Url;

    pub(in crate::http_processing) struct Mitm {
        domains: Box<[Pattern]>,
        exclusions: Box<[Pattern]>,
        ports: Box<[u16]>,
        authority: Arc<Authority>,
    }
    impl Mitm {
        pub(in crate::http_processing) fn compile(
            raw: RawMitm,
            ca: Option<&CaMaterial>,
        ) -> io::Result<Option<Arc<Self>>> {
            raw.validate_static()?;
            if !raw.enabled {
                return Ok(None);
            }
            let domains = patterns(&raw.domains)?;
            let exclusions = patterns(&raw.exclude_domains)?;
            let ca = ca.ok_or_else(invalid)?;
            ca.validate_size()?;
            let authority = Authority::load(&ca.certificate, &ca.private_key)?;
            let mut ports = raw.ports;
            ports.sort_unstable();
            ports.dedup();
            Ok(Some(Arc::new(Self {
                domains,
                exclusions,
                ports: ports.into(),
                authority,
            })))
        }
        pub(in crate::http_processing) fn identity(&self) -> [u8; 32] {
            self.authority.identity()
        }
        pub(in crate::http_processing) fn candidate_port(&self, port: u16) -> bool {
            self.ports.binary_search(&port).is_ok()
        }
        pub(in crate::http_processing) fn permits(&self, name: &str, port: u16) -> bool {
            let Ok(name) = crate::routing::normalize_domain_name(name) else {
                return false;
            };
            self.candidate_port(port)
                && !self.exclusions.iter().any(|p| p.matches(&name))
                && self.domains.iter().any(|p| p.matches(&name))
        }
        pub(in crate::http_processing) fn permits_url(&self, url: &Url) -> bool {
            url.scheme() == "https"
                && url
                    .host_str()
                    .zip(url.port_or_known_default())
                    .is_some_and(|(host, port)| self.permits(host, port))
        }
    }
    impl HttpContext {
        pub(in crate::http_processing) async fn intercept_tls<
            S: AsyncRead + AsyncWrite + Unpin + Send,
        >(
            &self,
            stream: &mut S,
            mut session: StreamSession,
            cancellation: CancellationToken,
        ) -> io::Result<Intercept> {
            let Some(policy) = self.policy().mitm() else {
                return Ok(Intercept::Transparent { prefix: Vec::new() });
            };
            if !policy.candidate_port(session.destination.port()) {
                return Ok(Intercept::Transparent { prefix: Vec::new() });
            }
            let mut sniffer = TcpSniffer::with_protocols(vec![SniffProtocol::Tls]);
            let outcome = tokio::select! {biased;()=cancellation.cancelled()=>return Ok(Intercept::Handled),result=sniffer.sniff(stream)=>result?};
            let prefix = sniffer.into_buffered();
            let SniffOutcome::Matched {
                protocol: SniffProtocol::Tls,
                domain,
            } = outcome
            else {
                // Includes both genuine ECH and GREASE. An outer cover name
                // does not authorize decrypting the hidden target.
                if self.policy().plain_port(session.destination.port())
                    && prefix.first().is_some_and(u8::is_ascii_uppercase)
                {
                    let mut replay = Replay::new(prefix, stream);
                    Box::pin(self.serve_h1(&mut replay, session, Scheme::Http, cancellation))
                        .await?;
                    return Ok(Intercept::Handled);
                }
                return Ok(Intercept::Transparent { prefix });
            };
            if !policy.permits(&domain, session.destination.port()) {
                return Ok(Intercept::Transparent { prefix });
            }
            session.capture_original();
            session.sniffed_domain = Some(domain.clone());
            let config = policy.authority.server_config(&domain)?;
            let replay = Replay::new(prefix, stream);
            let operation = async {
                let mut tls = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio_rustls::TlsAcceptor::from(config).accept_with(replay, |connection| {
                        connection.set_buffer_limit(Some(32 * 1024))
                    }),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "business TLS handshake timed out")
                })?
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "business TLS handshake failed")
                })?;
                // Keep the unused H1 body/relay state out of an H2 session.
                if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                    self.serve_h2(&mut tls, session, cancellation.clone()).await
                } else {
                    Box::pin(self.serve_h1(&mut tls, session, Scheme::Https, cancellation.clone()))
                        .await
                }
            };
            tokio::select! {biased;()=cancellation.cancelled()=>{},result=operation=>result?}
            Ok(Intercept::Handled)
        }
        pub(in crate::http_processing) fn permits_https(&self, url: &Url) -> bool {
            self.policy()
                .mitm()
                .is_some_and(|policy| policy.permits_url(url))
        }
    }
}
#[cfg(feature = "inbound-http")]
pub(in crate::http_processing) use enabled::Mitm;

#[cfg(all(test, feature = "inbound-http"))]
mod tests {
    use super::{Pattern, RawMitm};
    #[test]
    fn selective_domains_do_not_accept_suffix_confusion_or_ip_literals() {
        let p = Pattern::compile("*.example.com").unwrap();
        assert!(p.matches("api.example.com"));
        assert!(!p.matches("example.com"));
        assert!(!p.matches("notexample.com"));
        assert!(!p.matches("api.example.com.evil"));
        for name in ["*", "a*b.example", "127.0.0.1", "[::1]"] {
            assert!(Pattern::compile(name).is_err());
        }
    }

    #[test]
    fn static_mitm_validation_needs_no_private_material() {
        let input = r#"enabled: true
domains:
  - pattern: API.Example.COM.
  - pattern: '*.example.net'
exclude-domains:
  - pattern: private.example.net
"#;
        let policy: RawMitm = serde_yaml_ng::from_str(input).unwrap();
        policy.validate_static().unwrap();
        for input in [
            "domains: null",
            "ports: null",
            "exclude-domains: null",
            "domains: [{pattern: example.com}, {pattern: EXAMPLE.COM., enabled: false}]",
            "domains: [{pattern: '*.example.com'}, {pattern: '*.EXAMPLE.COM.'}]",
            "domains: [{pattern: '*', enabled: false}]",
            "enabled: true\ndomains: [{pattern: example.com, enabled: false}]",
            "enabled: true\ndomains: [{pattern: example.com}]\nports: []",
            "certificate: ignored\nprivate-key: ignored",
        ] {
            assert!(
                serde_yaml_ng::from_str::<RawMitm>(input)
                    .and_then(|raw| raw.validate_static().map_err(serde::de::Error::custom))
                    .is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn runtime_mitm_binds_private_identity_and_keeps_existing_authority() {
        use crate::http_processing::private_context::test_material;
        let settings: RawMitm = serde_yaml_ng::from_str(
            "enabled: true\ndomains: [{pattern: '*.example.com'}]\nexclude-domains: [{pattern: private.example.com}]",
        )
        .unwrap();
        assert!(super::enabled::Mitm::compile(settings.clone(), None).is_err());
        assert!(
            super::enabled::Mitm::compile(RawMitm::default(), None)
                .unwrap()
                .is_none()
        );
        let first_material = test_material();
        let first = super::enabled::Mitm::compile(settings.clone(), Some(&first_material))
            .unwrap()
            .unwrap();
        let first_identity = first.identity();
        assert_eq!(first_identity, first_material.identity().unwrap());
        assert!(first.permits("api.example.com", 443));
        assert!(!first.permits("example.com", 443));
        assert!(!first.permits("private.example.com", 443));
        assert!(!first.permits("api.example.com", 8443));
        drop(first_material);
        let second = super::enabled::Mitm::compile(settings, Some(&test_material()))
            .unwrap()
            .unwrap();
        assert_ne!(first.identity(), second.identity());
        assert_eq!(first.identity(), first_identity);
        assert!(first.permits("api.example.com", 443));
    }
}
