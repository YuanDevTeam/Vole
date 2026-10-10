use super::*;

pub(super) fn default_nameservers() -> Vec<String> {
    ["https://doh.pub/dns-query", "tls://223.5.5.5:853"]
        .map(str::to_owned)
        .to_vec()
}
pub(super) fn default_bootstrap() -> Vec<String> {
    ["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"]
        .map(str::to_owned)
        .to_vec()
}
pub(super) fn redir_host() -> String {
    "redir-host".into()
}
pub(super) fn default_ipv6_timeout() -> u64 {
    100
}

impl Default for DnsConfig {
    fn default() -> Self {
        // Empty targets are sufficient for the built-in DIRECT upstreams.
        let raw: RawDnsConfig = serde_yaml_ng::from_str("{}").expect("DNS defaults");
        raw.normalize(&RouteTargetsByName::new())
            .expect("valid DNS defaults")
    }
}
impl DnsConfig {
    pub(super) fn disabled() -> Result<Self> {
        Ok(Self::default())
    }
}

impl RawDnsConfig {
    pub(super) fn normalize(self, targets: &RouteTargetsByName) -> Result<DnsConfig> {
        let fake_ip = self.fake_ip()?;
        if self.enable && self.nameserver.is_empty() {
            return invalid("enabled DNS requires nameserver");
        }
        if self.default_nameserver.is_empty() {
            return invalid("default-nameserver requires at least one server");
        }
        if (self.respect_rules || !self.proxy_policies.is_empty())
            && self.proxy_nameserver.is_empty()
        {
            return invalid(
                "respect-rules and proxy-server-nameserver-policy require proxy-server-nameserver",
            );
        }
        let parse = |values: Vec<String>, route| {
            values
                .iter()
                .map(|value| parse_dns_nameserver(value, targets, route))
                .collect::<Result<Vec<_>>>()
        };
        let main_route = if self.respect_rules {
            DnsRoute::Rules
        } else {
            DnsRoute::Direct
        };
        let default_nameservers = parse(self.default_nameserver, DnsRoute::Direct)?;
        if default_nameservers
            .iter()
            .any(|server| matches!(server.address, DnsAddress::Domain(_)))
        {
            return invalid("default-nameserver requires literal IP addresses");
        }
        let fallback = self
            .fallback_filter
            .normalize(parse(self.fallback, main_route)?, self.fallback_lazy_query)?;
        Ok(DnsConfig {
            fallback,
            fake_ip,
            enable: self.enable,
            ipv6: self.ipv6,
            ipv6_timeout: Duration::from_millis(if self.ipv6_timeout == 0 {
                default_ipv6_timeout()
            } else {
                self.ipv6_timeout
            }),
            cache_max_size: if self.cache_max_size == 0 {
                crate::dns::MAX_CACHE_ENTRIES
            } else {
                self.cache_max_size
            },
            cache_algorithm: if self.cache_algorithm == "arc" {
                DnsCacheAlgorithm::Arc
            } else {
                DnsCacheAlgorithm::Lru
            },
            nameservers: parse(self.nameserver, main_route)?,
            nameserver_policies: normalize_dns_nameserver_policies(
                self.nameserver_policies,
                targets,
                main_route,
            )?,
            default_nameservers,
            proxy_nameservers: parse(self.proxy_nameserver, DnsRoute::Direct)?,
            proxy_policies: normalize_dns_nameserver_policies(
                self.proxy_policies,
                targets,
                DnsRoute::Direct,
            )?,
            direct_nameservers: parse(self.direct_nameserver, DnsRoute::Direct)?,
            direct_follow_policy: self.direct_follow_policy,
            use_hosts: self.use_hosts,
            use_system_hosts: self.use_system_hosts,
            hosts: vec![HostEntry {
                pattern: "localhost".into(),
                value: HostValue::Addresses(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            }],
        })
    }
}

pub(super) fn parse_dns_nameserver(
    input: &str,
    targets: &RouteTargetsByName,
    default_route: DnsRoute,
) -> Result<DnsNameserver> {
    let bad = || {
        VoleError::InvalidConfig(
            "invalid DNS upstream; supported transports are UDP, TCP, TLS and HTTP(S)".into(),
        )
    };
    let (endpoint, route) = match input.split_once('#') {
        Some((endpoint, fragment)) => {
            let name = percent_decode(fragment)?;
            let route = match name.as_str() {
                "DIRECT" => DnsRoute::Direct,
                "RULES" => DnsRoute::Rules,
                _ => targets
                    .get(&name)
                    .copied()
                    .map(DnsRoute::Route)
                    .ok_or_else(bad)?,
            };
            (endpoint, route)
        }
        None => (input, default_route),
    };
    if let Ok(address) = endpoint.parse::<IpAddr>() {
        return Ok(DnsNameserver {
            address: address.into(),
            transport: DnsTransport::Udp,
            port: 53,
            route,
            path: None,
        });
    }
    let endpoint = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("udp://{endpoint}")
    };
    let url = Url::parse(&endpoint).map_err(|_| bad())?;
    let (transport, default_port) = match url.scheme() {
        "udp" => (DnsTransport::Udp, 53),
        "tcp" => (DnsTransport::Tcp, 53),
        "tls" => (DnsTransport::Tls, 853),
        "https" => (DnsTransport::Https, 443),
        "http" => (DnsTransport::Http, 80),
        _ => return Err(bad()),
    };
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(bad());
    }
    let address = match url.host().ok_or_else(bad)? {
        Host::Ipv4(ip) => DnsAddress::Ip(ip.into()),
        Host::Ipv6(ip) => DnsAddress::Ip(ip.into()),
        Host::Domain(host) => match host.parse::<IpAddr>() {
            Ok(ip) => DnsAddress::Ip(ip),
            Err(_) => DnsAddress::Domain(crate::dns::canonicalize_name(host).map_err(|_| bad())?),
        },
    };
    let path = if matches!(transport, DnsTransport::Http | DnsTransport::Https) {
        Some(format!(
            "{}{}",
            if url.path().is_empty() {
                "/"
            } else {
                url.path()
            },
            url.query()
                .map(|value| format!("?{value}"))
                .unwrap_or_default()
        ))
    } else {
        if !matches!(url.path(), "" | "/") || url.query().is_some() {
            return Err(bad());
        }
        None
    };
    let port = url.port().unwrap_or(default_port);
    validate_port(port, "DNS nameserver")?;
    Ok(DnsNameserver {
        transport,
        address,
        port,
        route,
        path,
    })
}

fn percent_decode(input: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut iter = input.bytes();
    while let Some(byte) = iter.next() {
        if byte == b'%' {
            let a = iter.next().and_then(|b| (b as char).to_digit(16));
            let b = iter.next().and_then(|b| (b as char).to_digit(16));
            match (a, b) {
                (Some(a), Some(b)) => bytes.push((a * 16 + b) as u8),
                _ => return invalid("invalid DNS route encoding"),
            }
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| VoleError::InvalidConfig("invalid DNS route encoding".into()))
}

pub(super) fn normalize_hosts(
    raw: std::collections::BTreeMap<String, RawPolicyNameservers>,
) -> Result<Vec<HostEntry>> {
    let mut hosts = vec![HostEntry {
        pattern: "localhost".into(),
        value: HostValue::Addresses(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
    }];
    for (pattern, raw) in raw {
        let DnsPolicySelector::Domains(patterns) = normalize_dns_policy_selector(&pattern)? else {
            return invalid("hosts keys require domain patterns");
        };
        let values = match raw {
            RawPolicyNameservers::One(value) => vec![value],
            RawPolicyNameservers::Many(values) => values,
        };
        let value = if values.len() == 1 && values[0].parse::<IpAddr>().is_err() {
            if values[0] == "lan" {
                return invalid("hosts dynamic lan expansion is not supported");
            }
            HostValue::Alias(
                crate::dns::canonicalize_name(&values[0])
                    .map_err(|_| VoleError::InvalidConfig("invalid hosts alias".into()))?,
            )
        } else {
            let addresses = values
                .iter()
                .map(|value| {
                    value.parse::<IpAddr>().map_err(|_| {
                        VoleError::InvalidConfig("hosts requires IP addresses or one alias".into())
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if addresses.is_empty() {
                return invalid("hosts requires a value");
            }
            HostValue::Addresses(addresses)
        };
        for pattern in patterns {
            hosts.push(HostEntry {
                pattern,
                value: value.clone(),
            });
        }
    }
    crate::dns::hosts::validate(&hosts)
        .map_err(|_| VoleError::InvalidConfig("hosts contains a domain alias cycle".into()))?;
    Ok(hosts)
}
