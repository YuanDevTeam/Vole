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
        if self.prefer_h3 && !cfg!(feature = "dns-quic") {
            return invalid("DNS HTTP/3 support is disabled at build time");
        }
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
        if default_nameservers.iter().any(|server| {
            matches!(
                server.address,
                DnsAddress::Domain(_) | DnsAddress::Source(DnsSource::Dhcp(_))
            )
        }) {
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
            prefer_h3: self.prefer_h3,
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
    parse_dns_nameserver_with_route(input, Some(targets), default_route)
}

/// A node's private DNS fixes its dispatcher independently of the URL route
/// token. Keep the original URL so every keyed option is decoded once.
pub(super) fn parse_node_dns_nameserver(input: &str) -> Result<DnsNameserver> {
    parse_dns_nameserver_with_route(input, None, DnsRoute::Direct)
}

fn parse_dns_nameserver_with_route(
    input: &str,
    targets: Option<&RouteTargetsByName>,
    default_route: DnsRoute,
) -> Result<DnsNameserver> {
    let bad = || {
        VoleError::InvalidConfig(
            "invalid DNS upstream; supported transports are UDP, TCP, TLS, HTTP(S), QUIC, RCODE, system and DHCP"
                .into(),
        )
    };
    let (endpoint, fragment) = input.split_once('#').unwrap_or((input, ""));
    let (route_name, options) =
        parse_nameserver_options(fragment, !endpoint.starts_with("https://"))?;
    let route = match targets {
        Some(targets) if !route_name.is_empty() => match route_name.as_str() {
            "DIRECT" => DnsRoute::Direct,
            "RULES" => DnsRoute::Rules,
            _ => targets
                .get(&route_name)
                .copied()
                .map(DnsRoute::Route)
                .ok_or_else(bad)?,
        },
        _ => default_route,
    };
    // Special sources remain physical, but use the same query wrappers.
    let source = match endpoint {
        "system" | "system://" | "dhcp://system" => Some(DnsSource::System),
        endpoint if endpoint.starts_with("dhcp://") => {
            let interface = &endpoint[7..];
            crate::dns::source::validate_interface(interface).map_err(|_| bad())?;
            Some(DnsSource::Dhcp(interface.into()))
        }
        _ => None,
    };
    if let Some(source) = source {
        return Ok(DnsNameserver {
            address: DnsAddress::Source(source),
            transport: DnsTransport::Udp,
            port: 53,
            route: DnsRoute::Direct,
            path: None,
            http_auth: None,
            options,
        });
    }
    if let Ok(address) = endpoint.parse::<IpAddr>() {
        return Ok(DnsNameserver {
            address: address.into(),
            transport: DnsTransport::Udp,
            port: 53,
            route,
            path: None,
            http_auth: None,
            options,
        });
    }
    let endpoint = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("udp://{endpoint}")
    };
    let url = Url::parse(&endpoint).map_err(|_| bad())?;
    if url.scheme() == "rcode" {
        let host = url.host_str().ok_or_else(bad)?;
        let rcode = match host {
            "success" => 0,
            "format_error" => 1,
            "server_failure" => 2,
            "name_error" => 3,
            "not_implemented" => 4,
            "refused" => 5,
            _ => return Err(bad()),
        };
        // Mihomo selects the local client by URL host. Paths and query
        // parameters do not modify its behavior; a port changes the host.
        if url.port().is_some() {
            return Err(bad());
        }
        return Ok(DnsNameserver {
            transport: DnsTransport::Rcode(rcode),
            address: DnsAddress::Domain(host.to_owned()),
            port: 0,
            route,
            path: None,
            http_auth: None,
            options,
        });
    }
    let (transport, default_port) = match url.scheme() {
        "udp" => (DnsTransport::Udp, 53),
        "tcp" => (DnsTransport::Tcp, 53),
        "tls" => (DnsTransport::Tls, 853),
        "https" => (DnsTransport::Https, 443),
        "http" => (DnsTransport::Http, 80),
        "quic" if cfg!(feature = "dns-quic") => (DnsTransport::Quic, 853),
        "quic" => return invalid("DNS QUIC support is disabled at build time"),
        _ => return Err(bad()),
    };
    let http = matches!(transport, DnsTransport::Http | DnsTransport::Https);
    let has_userinfo = endpoint.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    });
    if (!http && has_userinfo) || url.fragment().is_some() {
        return Err(bad());
    }
    let http_auth = if http && has_userinfo {
        use base64::Engine as _;
        let mut value = percent_decode_bytes(url.username())?;
        value.push(b':');
        value.extend_from_slice(&percent_decode_bytes(url.password().unwrap_or_default())?);
        let encoded_len = value.len().div_ceil(3).saturating_mul(4);
        if encoded_len + 6 > crate::dns::MAX_HTTP_HEADER_BYTES {
            return invalid("DNS HTTP authentication exceeds the header budget");
        }
        Some(DnsHttpAuth(
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(value)
            )
            .into(),
        ))
    } else {
        None
    };
    let address = match url.host().ok_or_else(bad)? {
        Host::Ipv4(ip) => DnsAddress::Ip(ip.into()),
        Host::Ipv6(ip) => DnsAddress::Ip(ip.into()),
        Host::Domain(host) => match host.parse::<IpAddr>() {
            Ok(ip) => DnsAddress::Ip(ip),
            Err(_) => DnsAddress::Domain(crate::dns::canonicalize_name(host).map_err(|_| bad())?),
        },
    };
    let path = if http {
        // URL's browser-style parser resolves dot segments; Mihomo's URL.Path
        // keeps them. Decode the original path before rebuilding its escapes.
        let rest = endpoint.split_once("://").expect("DNS URL has a scheme").1;
        let path = rest.find(['/', '?']).map_or("/", |index| {
            let tail = &rest[index..];
            if tail.starts_with('/') {
                tail.split('?').next().unwrap_or("/")
            } else {
                "/"
            }
        });
        Some(normalize_http_path(path)?)
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
        http_auth,
        options,
    })
}

fn parse_nameserver_options(
    fragment: &str,
    ignore_h3: bool,
) -> Result<(String, DnsNameserverOptions)> {
    let fragment = percent_decode(fragment)?;
    let mut route = String::new();
    let mut params = std::collections::BTreeMap::new();
    for part in fragment.split('&') {
        if let Some((key, value)) = part.split_once('=') {
            params.insert(key, value);
        } else {
            route = part.to_owned();
        }
    }
    let mut options = DnsNameserverOptions::default();
    let mut disabled = std::collections::BTreeSet::new();
    for (key, value) in params {
        match key {
            "ecs" if !value.is_empty() => {
                let (address, prefix) = value
                    .split_once('/')
                    .map_or((value, None), |(a, p)| (a, Some(p)));
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| VoleError::InvalidConfig("invalid DNS ECS address".into()))?;
                let bits = if address.is_ipv4() { 32 } else { 128 };
                let prefix_len = prefix
                    .map_or(Ok(bits), |p| p.parse::<u8>())
                    .map_err(|_| VoleError::InvalidConfig("invalid DNS ECS prefix".into()))?;
                if prefix_len > bits {
                    return invalid("invalid DNS ECS prefix");
                }
                options.ecs = Some(DnsEcs {
                    address,
                    prefix_len,
                });
            }
            "ecs" => {}
            "ecs-override" => options.ecs_override = value == "true",
            "disable-ipv4" if value == "true" => {
                disabled.insert(1);
            }
            "disable-ipv6" if value == "true" => {
                disabled.insert(28);
            }
            "disable-ipv4" | "disable-ipv6" => {}
            key if key.starts_with("disable-qtype-") => {
                if value == "true"
                    && let Ok(kind) = key[14..].parse::<u16>()
                    && valid_disabled_type(kind)
                {
                    disabled.insert(kind);
                }
            }
            "skip-cert-verify" => options.skip_cert_verify = value == "true",
            "name-cert-verify" => {
                options.verification_name = normalize_verification_name(Some(value.to_owned()))?
            }
            "disable-reuse" => options.disable_reuse = value == "true",
            "h3" if value != "true" || ignore_h3 => {}
            "h3" if cfg!(feature = "dns-quic") => options.force_h3 = true,
            _ => return invalid("unsupported DNS upstream parameter"),
        }
    }
    options.disabled_types = disabled.into_iter().collect();
    Ok((route, options))
}

fn valid_disabled_type(kind: u16) -> bool {
    // Registered RR constructors in the fixed Mihomo miekg/dns v1.1.63
    // reference. Unknown 16-bit questions remain forwardable, not filters.
    matches!(kind, 1..=10 | 12..=21 | 23..=33 | 35..=37 | 39 | 41..=53 | 55..=65 | 99..=102 | 104..=109 | 128 | 249 | 250 | 255..=258 | 260 | 32768 | 32769)
}

#[cfg(test)]
mod upstream_options_tests {
    use super::*;

    #[test]
    fn dns_quic_feature_gates_and_plain_http_fragment() {
        let targets = RouteTargetsByName::new();
        let quic = parse_dns_nameserver("quic://dns.example", &targets, DnsRoute::Direct);
        let h3 = parse_dns_nameserver(
            "https://dns.example/dns-query#h3=true",
            &targets,
            DnsRoute::Direct,
        );
        let raw: RawDnsConfig = serde_yaml_ng::from_str("prefer-h3: true").unwrap();
        let preferred = raw.normalize(&targets);
        if cfg!(feature = "dns-quic") {
            let quic = quic.unwrap();
            assert_eq!(quic.port, 853);
            assert_eq!(quic.transport, DnsTransport::Quic);
            assert!(h3.unwrap().options.force_h3);
            assert!(preferred.unwrap().prefer_h3);
        } else {
            assert!(quic.is_err());
            assert!(h3.is_err());
            assert!(preferred.is_err());
        }
        let http = parse_dns_nameserver(
            "http://dns.example/dns-query#h3=true",
            &targets,
            DnsRoute::Direct,
        )
        .unwrap();
        assert_eq!(http.transport, DnsTransport::Http);
        assert!(!http.options.force_h3);
    }

    #[test]
    fn doh_url_clears_query_and_preserves_only_decoded_basic_identity() {
        use base64::Engine as _;
        let server = parse_dns_nameserver(
            "https://a%3Alice:p%40ss@dns.example/a%2Fb%20c?discard=secret#DIRECT&ecs=192.0.2.1",
            &RouteTargetsByName::new(),
            DnsRoute::Direct,
        )
        .unwrap();
        assert_eq!(server.path.as_deref(), Some("/a/b%20c"));
        assert_eq!(server.port, 443);
        let auth = server.http_auth.as_ref().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(auth.0.strip_prefix("Basic ").unwrap())
                .unwrap(),
            b"a:lice:p@ss"
        );
        assert_eq!(format!("{auth:?}"), "DnsHttpAuth([redacted])");
        let dot_path = parse_dns_nameserver(
            "https://dns.example/a/%2e%2e/b",
            &RouteTargetsByName::new(),
            DnsRoute::Direct,
        )
        .unwrap();
        assert_eq!(dot_path.path.as_deref(), Some("/a/../b"));
        for (userinfo, decoded) in [
            ("alice", &b"alice:"[..]),
            ("", &b":"[..]),
            ("%FF:%00", &b"\xff:\0"[..]),
        ] {
            let server = parse_dns_nameserver(
                &format!("http://{userinfo}@192.0.2.1?discard"),
                &RouteTargetsByName::new(),
                DnsRoute::Direct,
            )
            .unwrap();
            assert_eq!(server.path.as_deref(), Some("/"));
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(server.http_auth.unwrap().0.strip_prefix("Basic ").unwrap())
                    .unwrap(),
                decoded
            );
        }
    }

    #[test]
    fn upstream_options_decode_fragments_and_use_last_values() {
        let server = parse_dns_nameserver(
            "tls://192.0.2.1#DIRECT%26RULES%26ecs=2001:db8::7/57%26ecs-override=true%26disable-ipv4=true%26disable-ipv6=True%26disable-qtype-16=true%26disable-qtype-65280=true%26skip-cert-verify=false%26skip-cert-verify=true%26name-cert-verify=dns.example%26disable-reuse=true",
            &RouteTargetsByName::new(),
            DnsRoute::Direct,
        ).unwrap();
        assert_eq!(server.route, DnsRoute::Rules);
        assert_eq!(server.options.ecs.unwrap().prefix_len, 57);
        assert!(server.options.ecs_override);
        assert_eq!(&*server.options.disabled_types, &[1, 16]);
        assert!(server.options.skip_cert_verify);
        assert_eq!(
            server.options.verification_name.as_deref(),
            Some("dns.example")
        );
        assert!(server.options.disable_reuse);
        let parameter_only = parse_dns_nameserver(
            "192.0.2.1#disable-ipv6=true",
            &RouteTargetsByName::new(),
            DnsRoute::Rules,
        )
        .unwrap();
        assert_eq!(parameter_only.route, DnsRoute::Rules);
        assert_eq!(&*parameter_only.options.disabled_types, &[28]);
    }

    #[test]
    fn upstream_options_survive_system_dhcp_and_rcode_parsing() {
        for endpoint in [
            "system",
            "system://",
            "dhcp://system",
            "dhcp://en0",
            "rcode://refused",
        ] {
            let server = parse_dns_nameserver(
                &format!("{endpoint}#ecs=192.0.2.9&disable-ipv6=true"),
                &RouteTargetsByName::new(),
                DnsRoute::Direct,
            )
            .unwrap();
            assert_eq!(server.options.ecs.unwrap().prefix_len, 32);
            assert_eq!(&*server.options.disabled_types, &[28]);
            if endpoint == "dhcp://en0" {
                assert!(
                    matches!(server.address, DnsAddress::Source(DnsSource::Dhcp(ref interface)) if interface.as_ref() == "en0")
                );
            }
        }
    }
}

fn percent_decode(input: &str) -> Result<String> {
    String::from_utf8(percent_decode_bytes(input)?)
        .map_err(|_| VoleError::InvalidConfig("invalid DNS route encoding".into()))
}

fn percent_decode_bytes(input: &str) -> Result<Vec<u8>> {
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
    Ok(bytes)
}

fn normalize_http_path(path: &str) -> Result<String> {
    let mut result = String::new();
    for byte in percent_decode_bytes(path)? {
        // Mihomo rebuilds URL.Path without RawPath. Go encodePath retains
        // whole-path reserved separators except '?', with uppercase escapes.
        if byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&byte) {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(result, "%{byte:02X}").expect("writing a String cannot fail");
        }
        if result.len() > crate::dns::MAX_HTTP_HEADER_BYTES {
            return invalid("DNS HTTP path exceeds the header budget");
        }
    }
    if result.is_empty() {
        result.push('/');
    }
    Ok(result)
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
        let value = if values.as_slice() == ["lan"] {
            HostValue::Lan
        } else if values.len() == 1 && values[0].parse::<IpAddr>().is_err() {
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
