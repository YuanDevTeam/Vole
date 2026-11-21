//! Selective business TLS termination. Trust installation belongs to the host.
use super::origin::{Origin, dns_name, is_subdomain};
use std::{collections::BTreeSet, io};

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
        let name = dns_name(raw)?;
        Ok(Self {
            name: name.into(),
            suffix,
        })
    }

    fn matches(&self, name: &str) -> bool {
        if self.suffix {
            is_subdomain(name, &self.name)
        } else {
            name == self.name.as_ref()
        }
    }
}

pub(super) struct Patterns(Box<[Pattern]>);

impl Patterns {
    pub(super) fn compile(raw: &[String]) -> io::Result<Self> {
        if raw.len() > 64 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut output = Vec::with_capacity(raw.len());
        for entry in raw {
            let pattern = Pattern::compile(entry)?;
            if !seen.insert((pattern.name.clone(), pattern.suffix)) {
                return Err(invalid());
            }
            output.push(pattern);
        }
        Ok(Self(output.into()))
    }

    pub(super) fn matches(&self, host: &str) -> bool {
        self.0.iter().any(|pattern| pattern.matches(host))
    }

    pub(super) fn covers(&self, origin: &Origin) -> bool {
        if origin.is_wildcard() {
            self.0.iter().any(|pattern| {
                pattern.suffix
                    && (pattern.name.as_ref() == origin.host() || pattern.matches(origin.host()))
            })
        } else {
            self.matches(origin.host())
        }
    }

    pub(super) fn excludes_url(&self, url: &url::Url) -> bool {
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| self.matches(host.strip_suffix('.').unwrap_or(host)))
    }
}

#[cfg(feature = "inbound-http")]
mod enabled {
    use super::super::{HttpContext, Intercept, Scheme, authority::Authority, io::Replay};
    use super::{Origin, Patterns, dns_name, invalid};
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
        origins: Box<[Origin]>,
        exclusions: Arc<Patterns>,
        authority: Arc<Authority>,
    }
    impl Mitm {
        pub(in crate::http_processing) fn compile(
            origins: impl Iterator<Item = Origin>,
            exclusions: Arc<Patterns>,
            ca: Option<&CaMaterial>,
        ) -> io::Result<Option<Arc<Self>>> {
            let origins: Box<[_]> = origins.collect();
            if origins.is_empty() {
                return Ok(None);
            }
            let ca = ca.ok_or_else(invalid)?;
            ca.validate_size()?;
            let authority = Authority::load(&ca.certificate, &ca.private_key)?;
            Ok(Some(Arc::new(Self {
                origins,
                exclusions,
                authority,
            })))
        }

        pub(in crate::http_processing) fn identity(&self) -> [u8; 32] {
            self.authority.identity()
        }

        pub(in crate::http_processing) fn candidate_port(&self, port: u16) -> bool {
            self.origins.iter().any(|origin| origin.port() == port)
        }

        pub(in crate::http_processing) fn permits(&self, name: &str, port: u16) -> bool {
            let Ok(name) = dns_name(name) else {
                return false;
            };
            !self.exclusions.matches(&name)
                && self
                    .origins
                    .iter()
                    .any(|origin| origin.port() == port && origin.matches_host(&name))
        }

        pub(super) fn permits_url(&self, url: &Url, destination_port: u16) -> bool {
            !self.exclusions.excludes_url(url)
                && url.port_or_known_default() == Some(destination_port)
                && self.origins.iter().any(|origin| origin.matches_url(url))
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
                        connection.set_buffer_limit(Some(
                            crate::limits::ResourceLimits::default().tls_buffer_limit,
                        ))
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
        pub(in crate::http_processing) fn permits_https(
            &self,
            url: &Url,
            destination_port: u16,
        ) -> bool {
            self.policy()
                .mitm()
                .is_some_and(|policy| policy.permits_url(url, destination_port))
        }
    }
}
#[cfg(feature = "inbound-http")]
pub(in crate::http_processing) use enabled::Mitm;

#[cfg(all(test, feature = "inbound-http"))]
mod tests {
    use super::{Pattern, Patterns};
    use crate::http_processing::{
        config::{Document, HttpSettings},
        private_context::test_material,
    };

    #[test]
    fn selective_domains_do_not_accept_suffix_confusion_or_ip_literals() {
        let p = Pattern::compile("*.example.com").unwrap();
        assert!(p.matches("api.example.com"));
        assert!(p.matches("a.b.example.com"));
        assert!(!p.matches("example.com"));
        assert!(!p.matches("notexample.com"));
        assert!(!p.matches("api.example.com.evil"));
        for name in ["*", "a*b.example", "127.0.0.1", "[::1]"] {
            assert!(Pattern::compile(name).is_err());
        }
        assert!(Patterns::compile(&["*.example.com".into(), "*.EXAMPLE.COM.".into()]).is_err());
    }

    #[test]
    fn runtime_mitm_binds_private_identity_and_keeps_existing_authority() {
        let candidate = Document::parse(
            "targets: [{origins: ['https://api.example.com'], intercept-only: true}]",
        )
        .unwrap()
        .compile()
        .unwrap();
        let settings = HttpSettings {
            mitm_enabled: true,
            allow_intercept_only: true,
            ..Default::default()
        };
        assert!(candidate.bind_settings(&settings, None).is_err());
        assert!(
            candidate
                .bind_settings(&HttpSettings::default(), None)
                .unwrap()
                .mitm()
                .is_none()
        );

        let material = test_material();
        let first = candidate.bind_settings(&settings, Some(&material)).unwrap();
        let first = first.mitm().unwrap();
        let first_identity = first.identity();
        assert_eq!(first_identity, material.identity().unwrap());
        assert!(first.permits("API.example.com.", 443));
        assert!(!first.permits("example.com", 443));
        assert!(!first.permits("api.example.com", 8443));

        let second = candidate
            .bind_settings(&settings, Some(&test_material()))
            .unwrap();
        assert_ne!(first.identity(), second.mitm().unwrap().identity());
        assert_eq!(first.identity(), first_identity);

        let excluded = HttpSettings {
            exclude_domains: vec!["*.example.com".into()],
            ..settings
        };
        assert!(!candidate.requires_ca(&excluded).unwrap());
        assert!(
            candidate
                .bind_settings(&excluded, None)
                .unwrap()
                .mitm()
                .is_none()
        );
    }

    #[test]
    fn partial_wildcard_exclusions_apply_at_handshake_and_original_authority() {
        let candidate = Document::parse(
            "targets: [{origins: ['https://*.cdn.example.com:8443'], intercept-only: true}]",
        )
        .unwrap()
        .compile()
        .unwrap();
        let mut settings = HttpSettings {
            mitm_enabled: true,
            allow_intercept_only: true,
            exclude_domains: vec![
                "blocked.cdn.example.com".into(),
                "*.private.cdn.example.com".into(),
            ],
            ..Default::default()
        };
        let policy = candidate
            .bind_settings(&settings, Some(&test_material()))
            .unwrap();
        let mitm = policy.mitm().unwrap();
        for (host, permitted) in [
            ("open.cdn.example.com", true),
            ("deep.open.cdn.example.com", true),
            ("cdn.example.com", false),
            ("blocked.cdn.example.com", false),
            ("secret.private.cdn.example.com", false),
            ("notcdn.example.com", false),
        ] {
            let url = url::Url::parse(&format!("https://{host}:8443/path")).unwrap();
            assert_eq!(mitm.permits(host, 8443), permitted);
            assert_eq!(mitm.permits_url(&url, 8443), permitted);
            assert_eq!(policy.allows_target(&url), permitted);
            assert!(!mitm.permits_url(&url, 443));
        }
        settings.exclude_domains = vec!["*.example.com".into()];
        assert!(!candidate.requires_ca(&settings).unwrap());
        assert!(
            candidate
                .bind_settings(&settings, None)
                .unwrap()
                .mitm()
                .is_none()
        );
    }

    #[test]
    fn h3_fallback_uses_active_rewrites_and_the_original_authority() {
        let candidate = Document::parse(
            r#"
targets:
  - origins: ['https://*.cdn.example.com:8443']
    rules:
      - response:
          headers: [{set: {x-rewritten: yes}}]
  - origins: ['https://diagnostic.example.com:9443']
    intercept-only: true
  - origins: ['http://plain.example.com:8080']
    rules:
      - request: {url: {reject: true}}
  - origins: ['https://empty.example.com']
    rules:
      - response: {body: [{json-patch: []}]}
"#,
        )
        .unwrap()
        .compile()
        .unwrap();
        let settings = HttpSettings {
            mitm_enabled: true,
            allow_intercept_only: true,
            exclude_domains: vec!["*.private.cdn.example.com".into()],
            ..Default::default()
        };
        let material = test_material();
        let policy = candidate.bind_settings(&settings, Some(&material)).unwrap();
        for (host, port, expected) in [
            ("sub.cdn.example.com", 8443, true),
            ("deep.sub.cdn.example.com", 8443, true),
            ("cdn.example.com", 8443, false),
            ("a.private.cdn.example.com", 8443, false),
            ("sub.cdn.example.com", 443, false),
            ("diagnostic.example.com", 9443, false),
            ("plain.example.com", 8080, false),
            ("empty.example.com", 443, false),
        ] {
            let url = url::Url::parse(&format!("https://{host}:{port}/path")).unwrap();
            assert_eq!(
                policy.h3_fallback_for_udp(port, Some(host)),
                expected,
                "{url}"
            );
            assert_eq!(policy.h3_fallback_for_url(&url), expected, "{url}");
        }
        assert!(policy.h3_fallback_for_udp(8443, None));
        assert!(!policy.h3_fallback_for_udp(443, None));
        assert!(!policy.h3_fallback_for_udp(9443, None));
        for settings in [
            HttpSettings {
                mitm_enabled: false,
                ..settings.clone()
            },
            HttpSettings {
                rewrite_enabled: false,
                ..settings.clone()
            },
            HttpSettings {
                exclude_domains: vec!["*.cdn.example.com".into()],
                ..settings
            },
        ] {
            let policy = candidate.bind_settings(&settings, Some(&material)).unwrap();
            assert!(!policy.h3_fallback_for_udp(8443, None));
            assert!(!policy.h3_fallback_for_url(
                &url::Url::parse("https://sub.cdn.example.com:8443/path").unwrap()
            ));
        }
    }
}
