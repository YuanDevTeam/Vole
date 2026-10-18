//! Selective business TLS termination. Trust installation belongs to the host.
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawMitm {
    pub(super) domains: Vec<String>,
    #[serde(default)]
    pub(super) exclude_domains: Vec<String>,
    #[serde(default = "default_ports")]
    pub(super) ports: Vec<u16>,
    pub(super) certificate: String,
    pub(super) private_key: String,
}
fn default_ports() -> Vec<u16> {
    vec![443]
}

#[cfg(feature = "inbound-http")]
mod enabled {
    use super::super::{HttpContext, Intercept, Scheme, authority::Authority, io::Replay};
    use super::RawMitm;
    use crate::{
        session::StreamSession,
        tcp_sniffer::{SniffOutcome, SniffProtocol, TcpSniffer},
    };
    use std::{io, sync::Arc, time::Duration};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_util::sync::CancellationToken;
    use url::Url;

    pub(super) struct Pattern {
        name: Box<str>,
        suffix: bool,
    }
    impl Pattern {
        pub(super) fn compile(raw: &str) -> io::Result<Self> {
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
        pub(super) fn matches(&self, name: &str) -> bool {
            if self.suffix {
                name.strip_suffix(self.name.as_ref())
                    .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
            } else {
                name == self.name.as_ref()
            }
        }
    }
    fn invalid() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid selective TLS policy")
    }
    pub(in crate::http_processing) struct Mitm {
        domains: Box<[Pattern]>,
        exclusions: Box<[Pattern]>,
        ports: Box<[u16]>,
        authority: Arc<Authority>,
    }
    impl Mitm {
        pub(in crate::http_processing) fn compile(raw: RawMitm) -> io::Result<Arc<Self>> {
            if raw.domains.is_empty()
                || raw.domains.len() > 64
                || raw.exclude_domains.len() > 64
                || raw.ports.is_empty()
                || raw.ports.len() > 64
                || raw.ports.contains(&0)
            {
                return Err(invalid());
            }
            let domains = raw
                .domains
                .iter()
                .map(|s| Pattern::compile(s))
                .collect::<io::Result<Vec<_>>>()?;
            let exclusions = raw
                .exclude_domains
                .iter()
                .map(|s| Pattern::compile(s))
                .collect::<io::Result<Vec<_>>>()?;
            let authority = Authority::load(&raw.certificate, &raw.private_key)?;
            let mut ports = raw.ports;
            ports.sort_unstable();
            ports.dedup();
            Ok(Arc::new(Self {
                domains: domains.into(),
                exclusions: exclusions.into(),
                ports: ports.into(),
                authority,
            }))
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
                    self.serve_h1(&mut replay, session, Scheme::Http, cancellation)
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
                if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                    self.serve_h2(&mut tls, session, cancellation.clone()).await
                } else {
                    self.serve_h1(&mut tls, session, Scheme::Https, cancellation.clone())
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
    use super::enabled::Pattern;
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
}
