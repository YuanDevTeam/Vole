//! MASQUE's mode-specific Mihomo fields and dedicated ECDSA key policy.
use super::{
    DnsNameserver, ProxyProtocol, deserialize_present_option, invalid, validate_host, validate_port,
};
use crate::Result;
use serde::Deserialize;

const CONNECT_URI: &str = "https://cloudflareaccess.com";
const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasqueNetwork {
    Quic,
    H2,
    H3L4Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueIpStackOptions {
    pub mode: String,
    pub congestion_controller: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MasqueOutboundConfig {
    pub address: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub server_name: String,
    pub network: MasqueNetwork,
    pub ip: String,
    pub ipv6: String,
    pub uri: String,
    pub mtu: i64,
    pub udp: bool,
    pub handshake_timeout: i64,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub congestion_controller: String,
    pub ip_stack: MasqueIpStackOptions,
    pub remote_dns_resolve: bool,
    pub dns: Vec<DnsNameserver>,
    pub local_prefixes: [Option<(std::net::IpAddr, u8)>; 2],
}

impl std::fmt::Debug for MasqueOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MasqueOutboundConfig")
            .field("network", &self.network)
            .field("udp", &self.udp)
            .finish_non_exhaustive()
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawIpStack {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    congestion_controller: String,
}

impl RawIpStack {
    fn normalize(self) -> Result<MasqueIpStackOptions> {
        let mode = self.mode.to_lowercase();
        let mode = if mode.is_empty() { "auto".into() } else { mode };
        let congestion_controller = self.congestion_controller.to_lowercase();
        if mode != "auto" {
            return invalid("MASQUE IP stack mode is not supported");
        }
        if !matches!(congestion_controller.as_str(), "" | "cubic") {
            return invalid("MASQUE IP stack congestion controller is not supported");
        }
        Ok(MasqueIpStackOptions {
            mode,
            congestion_controller,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawMasque {
    name: String,
    server: String,
    port: u16,
    private_key: String,
    public_key: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ipv6: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    mtu: i64,
    #[serde(default)]
    udp: bool,
    #[serde(default)]
    handshake_timeout: i64,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default)]
    name_cert_verify: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    congestion_controller: String,
    #[serde(default)]
    ip_stack: RawIpStack,
    #[serde(default)]
    remote_dns_resolve: bool,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    dialer_proxy: Option<String>,
}

impl std::fmt::Debug for RawMasque {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("RawMasque").finish_non_exhaustive()
    }
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<RawMasque, D::Error> {
    RawMasque::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid MASQUE configuration fields"))
}

impl RawMasque {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-masque") {
            return invalid("MASQUE outbound support is disabled at build time");
        }
        validate_host(&self.server, "MASQUE server")?;
        validate_port(self.port, "MASQUE")?;
        if self.handshake_timeout < 0 {
            return invalid("MASQUE handshake timeout must be non-negative");
        }
        // The reference validates this object even when L4 does not create an
        // IP stack. Unsupported stacks are not aliases for Vole's stack.
        let ip_stack = self.ip_stack.normalize()?;
        #[cfg(feature = "outbound-masque")]
        crate::security::masque::validate_keys(&self.private_key, &self.public_key)
            .map_err(|_| crate::VoleError::InvalidConfig("invalid MASQUE ECDSA keys".into()))?;
        let network = match self.network.as_str() {
            "h2" => MasqueNetwork::H2,
            "h3-l4proxy" => MasqueNetwork::H3L4Proxy,
            _ => MasqueNetwork::Quic,
        };
        let dns = if self.remote_dns_resolve && !self.dns.is_empty() {
            self.dns
                .iter()
                .map(|nameserver| super::dns::parse_node_dns_nameserver(nameserver))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let server_name = if self.sni.is_empty() {
            match network {
                MasqueNetwork::H3L4Proxy => L4_CONNECT_SNI,
                MasqueNetwork::Quic | MasqueNetwork::H2 => CONNECT_SNI,
            }
            .into()
        } else {
            self.sni
        };
        validate_host(&server_name, "MASQUE sni")?;
        let mtu = if self.mtu == 0 { 1280 } else { self.mtu };
        let uri = if self.uri.is_empty() {
            CONNECT_URI.into()
        } else {
            self.uri
        };
        let mut local_prefixes = [None; 2];
        if network != MasqueNetwork::H3L4Proxy {
            for (index, (value, default_bits)) in
                [(&self.ip, 32), (&self.ipv6, 128)].into_iter().enumerate()
            {
                if !value.is_empty() {
                    let (address, bits) = value
                        .rsplit_once('/')
                        .map_or((value.as_str(), None), |(address, bits)| {
                            (address, Some(bits))
                        });
                    let address = address.parse::<std::net::IpAddr>().map_err(|_| {
                        crate::VoleError::InvalidConfig("invalid MASQUE local address".into())
                    })?;
                    let bits = match bits {
                        Some(bits) => bits.parse::<u8>().map_err(|_| {
                            crate::VoleError::InvalidConfig("invalid MASQUE address prefix".into())
                        })?,
                        None => default_bits,
                    };
                    if bits > if address.is_ipv4() { 32 } else { 128 } {
                        return invalid("invalid MASQUE address prefix");
                    }
                    local_prefixes[index] = Some((address, bits));
                }
            }
            let mtu = usize::try_from(mtu)
                .map_err(|_| crate::VoleError::InvalidConfig("invalid MASQUE MTU".into()))?;
            #[cfg(feature = "outbound-masque")]
            {
                let client = vole_netstack::ClientConfig {
                    prefixes: local_prefixes.map(|prefix| {
                        prefix.map(|(address, prefix_len)| vole_netstack::ClientPrefix {
                            address,
                            prefix_len,
                        })
                    }),
                    receive_packet_limit: vole_netstack::MAX_RECEIVE_PACKET_SIZE,
                    path_mtu_discovery: true,
                }
                .validate(mtu)
                .map_err(|_| {
                    crate::VoleError::InvalidConfig("invalid MASQUE client addresses or MTU".into())
                })?;
                local_prefixes = client
                    .prefixes
                    .map(|prefix| prefix.map(|prefix| (prefix.address, prefix.prefix_len)));
            }
            if uri.contains(['{', '}'])
                || url::Url::parse(&uri)
                    .ok()
                    .is_none_or(|url| url.host_str().is_none())
            {
                return invalid("invalid MASQUE CONNECT-IP URI");
            }
        }
        // L4 never parses the local addresses or URI and never applies MTU
        // or a positive handshake timeout. Retain their signed/raw values.
        let udp = self.udp && network != MasqueNetwork::H3L4Proxy;
        Ok((
            self.name,
            self.dialer_proxy,
            udp,
            ProxyProtocol::Masque(MasqueOutboundConfig {
                address: self.server,
                port: self.port,
                private_key: self.private_key,
                public_key: self.public_key,
                server_name,
                network,
                ip: self.ip,
                ipv6: self.ipv6,
                uri,
                mtu,
                udp,
                handshake_timeout: self.handshake_timeout,
                skip_cert_verify: self.skip_cert_verify,
                name_cert_verify: self.name_cert_verify,
                congestion_controller: self.congestion_controller,
                ip_stack,
                remote_dns_resolve: self.remote_dns_resolve,
                dns,
                local_prefixes,
            }),
        ))
    }
}

#[cfg(all(test, feature = "outbound-masque"))]
mod tests {
    use super::*;
    use crate::config::Config;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boring::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };
    use serde_json::{Value, json};

    fn node() -> Value {
        let key =
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
        let private = STANDARD.encode(key.private_key_to_der().unwrap());
        let public = STANDARD.encode(PKey::from_ec_key(key).unwrap().public_key_to_der().unwrap());
        json!({
            "name": "edge", "type": "masque", "server": "cover.invalid", "port": 443,
            "private-key": private, "public-key": public, "network": "h3-l4proxy"
        })
    }

    fn parse(node: Value) -> Result<Config> {
        Config::parse_yaml(&serde_json::to_vec(&json!({"proxies": [node]})).unwrap())
    }

    fn options(config: &Config) -> &MasqueOutboundConfig {
        let ProxyProtocol::Masque(options) = &config.proxies[0].protocol else {
            panic!("MASQUE node");
        };
        options
    }

    #[test]
    fn masque_l4_normalization_keeps_noop_fields_and_disables_business_udp() {
        let config = parse(node()).unwrap();
        assert_eq!(options(&config).server_name, L4_CONNECT_SNI);
        assert_eq!(options(&config).uri, CONNECT_URI);
        assert_eq!(options(&config).mtu, 1280);
        let mut raw = node();
        for (key, value) in [
            ("ip", json!("not an IP")),
            ("ipv6", json!("also not an IP")),
            ("uri", json!("not a URI")),
            ("mtu", json!(-1)),
            ("udp", json!(true)),
            ("handshake-timeout", json!(12)),
            ("name-cert-verify", json!("not a hostname")),
            ("congestion-controller", json!("unknown-default")),
            ("dns", json!(["not a nameserver"])),
            (
                "ip-stack",
                json!({"mode": "AUTO", "congestion-controller": "CUBIC"}),
            ),
        ] {
            raw[key] = value;
        }
        let config = parse(raw).unwrap();
        let options = options(&config);
        assert!(!config.proxies[0].udp && !options.udp);
        assert_eq!(options.ip, "not an IP");
        assert_eq!(options.uri, "not a URI");
        assert_eq!(options.mtu, -1);
        assert_eq!(options.handshake_timeout, 12);
        assert_eq!(options.name_cert_verify, "not a hostname");
        assert_eq!(options.ip_stack.mode, "auto");
        assert_eq!(options.ip_stack.congestion_controller, "cubic");
        let debug = format!("{:?}", config.proxies[0]);
        assert!(!debug.contains(&options.private_key));
        assert!(!debug.contains(&options.public_key));
        assert!(!debug.contains(&options.address));
    }

    #[test]
    fn removed_quic_tuning_fields_are_rejected_in_all_modes() {
        for network in ["h2", "quic", "h3-l4proxy"] {
            for (field, value) in [("cwnd", json!(16)), ("bbr-profile", json!("standard"))] {
                let mut raw = node();
                raw["network"] = json!(network);
                raw["ip"] = json!("192.0.2.10");
                raw[field] = value;
                assert!(parse(raw).is_err());
            }
        }
    }

    #[test]
    fn masque_ip_defaults_and_mode_consumers_are_explicit() {
        for network in [None, Some(""), Some("quic"), Some("unknown")] {
            let mut raw = node();
            raw["ip"] = json!("192.0.2.10");
            raw["udp"] = json!(true);
            if let Some(network) = network {
                raw["network"] = json!(network);
            } else {
                raw.as_object_mut().unwrap().remove("network");
            }
            let config = parse(raw).unwrap();
            let options = options(&config);
            assert_eq!(options.network, MasqueNetwork::Quic);
            assert_eq!(options.mtu, 1280);
            assert_eq!(options.server_name, CONNECT_SNI);
            assert_eq!(
                options.local_prefixes[0],
                Some((std::net::IpAddr::from([192, 0, 2, 10]), 32))
            );
            assert!(options.udp && config.proxies[0].udp);
        }
        let mut raw = node();
        raw["network"] = json!("h2");
        raw["ip"] = json!("192.0.2.10");
        assert_eq!(options(&parse(raw).unwrap()).network, MasqueNetwork::H2);
        let mut raw = node();
        raw["network"] = json!("quic");
        raw["ip"] = json!("192.0.2.10/24");
        raw["ipv6"] = json!("192.0.2.11/32");
        raw["mtu"] = json!(68);
        let config = parse(raw.clone()).unwrap();
        assert_eq!(options(&config).local_prefixes.iter().flatten().count(), 2);
        raw["ipv6"] = json!("2001:db8::1");
        assert!(parse(raw.clone()).is_err());
        raw["mtu"] = json!(1280);
        assert!(parse(raw.clone()).is_ok());
        raw["uri"] = json!("https://example.invalid/{target}");
        assert!(parse(raw).is_err());
        let mut raw = node();
        raw["remote-dns-resolve"] = json!(true);
        raw["dns"] = json!([]);
        assert!(parse(raw.clone()).is_ok());
        raw["dns"] = json!(["tcp://192.0.2.53"]);
        assert_eq!(options(&parse(raw).unwrap()).dns.len(), 1);
        for (field, value) in [
            ("handshake-timeout", json!(-1)),
            ("ip-stack", json!({"mode": "mips"})),
            ("ip-stack", json!({"congestion-controller": "bbr3"})),
            ("private-key", json!("invalid-private-key")),
            ("certificate", json!("must not be a TLS identity field")),
            ("client-fingerprint", json!("chrome")),
            ("ip-stack", json!({"hidden-field": true})),
        ] {
            let mut raw = node();
            raw[field] = value;
            assert!(parse(raw).is_err());
        }
    }

    #[test]
    fn masque_node_dns_activation_preserves_wrappers_and_physical_sources() {
        use crate::config::{DnsAddress, DnsRoute, DnsSource, DnsTransport};
        let mut raw = node();
        raw["dns"] = json!(["not a nameserver"]);
        assert!(options(&parse(raw.clone()).unwrap()).dns.is_empty());
        raw["remote-dns-resolve"] = json!(true);
        assert!(parse(raw.clone()).is_err());
        raw["dns"] = json!([
            "tcp://192.0.2.53#unused-route&ecs=192.0.2.255/25&disable-ipv6=true",
            "system#unused-route&disable-ipv4=true",
            "dhcp://physical0"
        ]);
        let config = parse(raw).unwrap();
        let dns = &options(&config).dns;
        assert_eq!(dns.len(), 3);
        assert!(
            dns.iter()
                .all(|nameserver| nameserver.route == DnsRoute::Direct)
        );
        assert_eq!(dns[0].transport, DnsTransport::Tcp);
        assert!(dns[0].options.ecs.is_some());
        assert!(dns[0].options.disabled_types.contains(&28));
        assert!(matches!(
            dns[1].address,
            DnsAddress::Source(DnsSource::System)
        ));
        assert!(dns[1].options.disabled_types.contains(&1));
        assert!(
            matches!(&dns[2].address, DnsAddress::Source(DnsSource::Dhcp(interface)) if interface.as_ref() == "physical0")
        );
    }

    #[test]
    fn masque_provider_overrides_reach_the_dedicated_policy() {
        let config = Config::parse_yaml(&serde_json::to_vec(&json!({
            "proxy-providers": {"nodes": {
                "type": "inline",
                "override": {"skip-cert-verify": true, "name-cert-verify": "placeholder", "udp": true},
                "payload": [node()]
            }}
        })).unwrap()).unwrap();
        assert!(options(&config).skip_cert_verify);
        assert_eq!(options(&config).name_cert_verify, "placeholder");
        assert!(!config.proxies[0].udp);
    }
}
