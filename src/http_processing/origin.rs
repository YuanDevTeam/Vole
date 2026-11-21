//! Canonical network scopes shared by rule matching and TLS admission.
use super::{config::invalid, rules::checked_url};
use std::io;
use url::{Host, Url};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Origin {
    https: bool,
    host: Box<str>,
    port: u16,
    wildcard: bool,
}

impl Origin {
    pub(super) fn parse(input: &str) -> io::Result<Self> {
        let (scheme, authority) = input.split_once("://").ok_or_else(invalid)?;
        let (wildcard, authority) = authority
            .strip_prefix("*.")
            .map_or((false, authority), |suffix| (true, suffix));
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@', '*', '%'])
            || authority.ends_with(':')
        {
            return Err(invalid());
        }
        let url = if wildcard {
            checked_url(&format!("{scheme}://{authority}"))?
        } else {
            checked_url(input)?
        };
        let https = url.scheme() == "https";
        let host = match url.host().ok_or_else(invalid)? {
            Host::Domain(host) => dns_name(host)?,
            Host::Ipv4(ip) if !https && !wildcard => ip.to_string(),
            Host::Ipv6(ip) if !https && !wildcard => format!("[{ip}]"),
            _ => return Err(invalid()),
        };
        if wildcard && psl::domain_str(&host).is_none() {
            return Err(invalid());
        }
        Ok(Self {
            https,
            host: host.into(),
            port: url.port_or_known_default().ok_or_else(invalid)?,
            wildcard,
        })
    }

    pub(super) fn matches_url(&self, url: &Url) -> bool {
        url.scheme() == self.scheme()
            && url.port_or_known_default() == Some(self.port)
            && url
                .host_str()
                .is_some_and(|host| self.matches_host(host.strip_suffix('.').unwrap_or(host)))
    }

    pub(super) fn matches_host(&self, host: &str) -> bool {
        if self.wildcard {
            is_subdomain(host, &self.host)
        } else {
            host == self.host.as_ref()
        }
    }

    pub(super) fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    pub(super) fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    pub(super) fn is_https(&self) -> bool {
        self.https
    }

    pub(super) fn host(&self) -> &str {
        &self.host
    }

    pub(super) fn port(&self) -> u16 {
        self.port
    }
}

pub(super) fn is_subdomain(host: &str, suffix: &str) -> bool {
    host.strip_suffix(suffix)
        .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
}

pub(super) fn dns_name(host: &str) -> io::Result<String> {
    let name = crate::routing::normalize_domain_name(host).map_err(|_| invalid())?;
    if !matches!(
        rustls::pki_types::ServerName::try_from(name.as_str()),
        Ok(rustls::pki_types::ServerName::DnsName(_))
    ) {
        return Err(invalid());
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomains_are_dns_suffix_scopes_with_an_exact_scheme_and_port() {
        let scope = Origin::parse("https://*.MEDIA.example.COM.:8443").unwrap();
        assert_eq!(scope.host(), "media.example.com");
        assert!(scope.is_wildcard());
        for (url, matches) in [
            ("https://a.media.example.com:8443/v1", true),
            ("https://a.b.media.example.com.:8443/v1", true),
            ("https://media.example.com:8443/v1", false),
            ("https://badmedia.example.com:8443/v1", false),
            ("https://a.media.example.com/v1", false),
            ("http://a.media.example.com:8443/v1", false),
        ] {
            assert_eq!(scope.matches_url(&Url::parse(url).unwrap()), matches);
        }
        for input in [
            "https://*",
            "https://*.com",
            "https://*.co.uk",
            "https://*.github.io",
            "https://*.127.0.0.1",
            "http://*.[::1]",
            "https://api.*.example.com",
        ] {
            assert!(Origin::parse(input).is_err(), "{input}");
        }
    }
}
