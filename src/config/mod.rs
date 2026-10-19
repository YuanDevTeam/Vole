//! Strict parsing for the current Vole YAML configuration.
mod anytls;
mod fake_ip;
mod tun_network;
pub use tun_network::{TunAddress6, TunNetworkConfig};
#[cfg(any(feature = "invoke", test))]
pub(crate) mod live_update;
pub use anytls::AnyTlsSessionOptions;
mod fallback;
mod grpc;
mod sing_mux;
mod sniffer;
pub use fake_ip::{FakeIpConfig, FakeIpFilterMode, FakeIpRange};
pub use fallback::DnsFallbackConfig;
pub use grpc::GrpcOptions;
pub use sing_mux::{SingMuxConfig, SingMuxProtocol};
mod http_proxy;
mod ip_version;
mod masque;
mod mieru;
mod trusttunnel;
pub use http_proxy::HttpOutboundConfig;
pub use ip_version::IpVersion;
pub use masque::{MasqueIpStackOptions, MasqueNetwork, MasqueOutboundConfig};
pub use mieru::{MieruHandshake, MieruMultiplexing, MieruOutboundConfig, MieruTransport};
pub use trusttunnel::{TrustTunnelOutboundConfig, TrustTunnelPoolOptions};

mod groups;
pub(crate) use groups::status_ranges;
pub use groups::{BalanceHashKey, BalanceStrategy, GroupKind, HealthCheckConfig, ProfileConfig};

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use url::{Host, Url};
use uuid::Uuid;

use crate::{Result, VoleError};

mod dns;
mod egress;
pub use egress::EgressOptions;
mod domain_regex;
mod functional;
mod identity_files;
mod ip_suffix;
mod process;
mod security;
pub use process::{FindProcessMode, ProcessField, ProcessRule, UidRange};
mod name_regex;
mod override_expr;
pub mod providers;
mod rule_provider;
pub(crate) mod rules;
pub use domain_regex::{DomainRegex, MatchFailure, RuleDecision};
pub use ip_suffix::IpSuffix;
mod scalar;
pub use rule_provider::RuleCollection;
pub(crate) mod yaml;
pub use rules::RuleInboundType;
use rules::parse_rule;

mod credentials;
pub use credentials::{ProxyAccess, ProxyAccessRules, ProxyCredentials};
mod controller;
pub use controller::{ControllerCors, ControllerTls};
mod ech;
pub use ech::StaticEchConfig;
mod quic;
pub use quic::QuicReceiveWindow;
mod hysteria2;
mod hysteria2_realm;
pub use hysteria2::{Hysteria2Gecko, Hysteria2Hopping, Hysteria2OutboundConfig};
pub use hysteria2_realm::Hysteria2Realm;
mod wireguard;
pub use wireguard::{WireGuardKey, WireGuardOutboundConfig, WireGuardPeerConfig};
mod tuic;
pub use tuic::{TuicCongestion, TuicOutboundConfig, TuicUdpMode};
mod jls;
pub use jls::JlsConfig;
mod tls_trust;
pub use tls_trust::TlsTrustConfig;
mod shadowsocks;
mod shadowsocks_plugin;
pub use shadowsocks::{ShadowTlsConfig, ShadowsocksCipher, ShadowsocksOutboundConfig};
pub use shadowsocks_plugin::ShadowsocksPlugin;
mod trojan;
pub use trojan::{TrojanOutboundConfig, TrojanTransport, WebSocketHandshake};
mod vless;
pub use vless::VlessStreamOptions;
pub(crate) mod xhttp;
pub use xhttp::{XHttpHeaders, XHttpRequestOptions, XHttpReuseConfig, XHttpVersion};
mod vmess;
pub use vmess::StreamTransport as VmessTransport;
pub use vmess::{StreamTransport, VmessCipher, VmessOutboundConfig, VmessPacketEncoding};
#[cfg(all(
    test,
    feature = "outbound-anytls",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-socks5",
    feature = "inbound-http",
    feature = "inbound-socks5"
))]
mod tls_policy_tests;

#[cfg(feature = "invoke")]
mod measure;

#[cfg(feature = "invoke")]
pub(crate) use measure::MeasureConfig;

pub const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RULES: usize = 65_536;
pub const MAX_RULE_BYTES: usize = 16 * 1024;
pub const MAX_RULES_TOTAL_BYTES: usize = MAX_CONFIG_BYTES;
pub const MAX_SNIFFER_PORT_ITEMS: usize = 64;
pub const MAX_GEOX_URL_BYTES: usize = 4_096;
pub const MAX_ANYTLS_PASSWORD_BYTES: usize = 1_024;
pub const GEO_UPDATE_INTERVAL_HOURS: u64 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub tls: TlsTrustConfig,
    pub ipv6: bool,
    pub proxies: Vec<ProxyConfig>,
    pub proxy_groups: Vec<SelectProxyGroupConfig>,
    pub mode: Mode,
    pub log_level: LogLevel,
    pub global_ua: String,
    pub etag_support: bool,
    pub unified_delay: bool,
    pub connections: ConnectionSettings,
    pub find_process_mode: FindProcessMode,
    pub egress: EgressOptions,
    pub profile: ProfileConfig,
    pub geodata_update: Option<GeoDataUpdateConfig>,
    pub external_controller: Option<ExternalControllerConfig>,
    pub inbounds: Vec<InboundConfig>,
    pub mixed_port: Option<u16>,
    pub tun: TunConfig,
    pub sniffer: SnifferConfig,
    pub dns: DnsConfig,
    pub rules: Vec<RuleSpec>,
    pub sub_rules: Vec<NamedRuleProgram>,
    pub provider_members: HashMap<String, Vec<String>>,
    pub providers: Option<std::sync::Arc<providers::ProviderTemplate>>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl TryFrom<String> for Mode {
    type Error = &'static str;
    fn try_from(value: String) -> std::result::Result<Self, &'static str> {
        match value.to_ascii_lowercase().as_str() {
            "rule" => Ok(Self::Rule),
            "global" => Ok(Self::Global),
            "direct" => Ok(Self::Direct),
            _ => Err("mode must be rule, global, or direct"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum LogLevel {
    Silent,
    Error,
    Warning,
    #[default]
    Info,
    Debug,
}

impl TryFrom<String> for LogLevel {
    type Error = &'static str;
    fn try_from(value: String) -> std::result::Result<Self, &'static str> {
        match value.to_ascii_lowercase().as_str() {
            "silent" => Ok(Self::Silent),
            "error" => Ok(Self::Error),
            "warning" => Ok(Self::Warning),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            _ => Err("log-level must be silent, error, warning, info, or debug"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExternalControllerConfig {
    pub listen: SocketAddr,
    pub secret: Option<String>,
    pub http_enabled: bool,
    pub tls_listen: Option<SocketAddr>,
    pub cors: ControllerCors,
    pub server_tls: ControllerTls,
}

impl Default for ExternalControllerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            secret: None,
            http_enabled: true,
            tls_listen: None,
            cors: ControllerCors::default(),
            server_tls: ControllerTls::default(),
        }
    }
}

impl std::fmt::Debug for ExternalControllerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalControllerConfig")
            .field("listen", &self.listen)
            .field("authenticated", &self.secret.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataUpdateConfig {
    pub geodata_mode: bool,
    pub urls: GeoDataUrls,
    pub auto_update: bool,
    pub interval_hours: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GeoDataUrls {
    pub geoip: String,
    pub mmdb: String,
    pub geosite: String,
    pub asn: String,
}
impl std::fmt::Debug for GeoDataUrls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoDataUrls")
            .field("geoip", &crate::resource::http::source_origin(&self.geoip))
            .field("mmdb", &crate::resource::http::source_origin(&self.mmdb))
            .field(
                "geosite",
                &crate::resource::http::source_origin(&self.geosite),
            )
            .field("asn", &crate::resource::http::source_origin(&self.asn))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub network: TunNetworkConfig,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub enable: bool,
    pub mtu: u16,
    pub file_descriptor: i32,
    pub device: String,
    pub dns_hijack: Vec<SocketAddr>,
    pub udp_timeout: Duration,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            network: TunNetworkConfig::default(),
            auto_route: cfg!(target_os = "linux"),
            auto_detect_interface: cfg!(target_os = "linux"),
            enable: false,
            mtu: default_mtu(),
            file_descriptor: 0,
            device: String::new(),
            dns_hijack: vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53))],
            udp_timeout: Duration::from_secs(300),
        }
    }
}

impl TunConfig {
    /// Match Mihomo's TUN DNS targets: exact endpoints, or any destination
    /// on port 53 when a configured endpoint has an unspecified IP address.
    #[must_use]
    pub fn hijacks_dns(&self, destination: SocketAddr) -> bool {
        self.dns_hijack.iter().any(|target| {
            *target == destination || (target.ip().is_unspecified() && destination.port() == 53)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnifferConfig {
    pub enable: bool,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
    pub force_domain: Vec<DnsPolicySelector>,
    pub skip_domain: Vec<DnsPolicySelector>,
    pub skip_src_address: Vec<RuleSpec>,
    pub skip_dst_address: Vec<RuleSpec>,
    pub http_override: bool,
    pub tls_override: bool,
    pub quic_override: bool,
    pub http_ports: Box<[PortRange]>,
    pub tls_ports: Box<[PortRange]>,
    pub quic_ports: Box<[PortRange]>,
}

impl SnifferConfig {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enable: false,
            force_dns_mapping: true,
            parse_pure_ip: true,
            force_domain: Vec::new(),
            skip_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            http_override: true,
            tls_override: true,
            quic_override: true,
            http_ports: Box::new([]),
            tls_ports: Box::new([]),
            quic_ports: Box::new([]),
        }
    }

    #[must_use]
    pub fn matches_http_port(&self, port: u16) -> bool {
        port_ranges_contain(&self.http_ports, port)
    }

    #[must_use]
    pub fn matches_tls_port(&self, port: u16) -> bool {
        port_ranges_contain(&self.tls_ports, port)
    }

    #[must_use]
    pub fn matches_quic_port(&self, port: u16) -> bool {
        port_ranges_contain(&self.quic_ports, port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub fake_ip: FakeIpConfig,
    pub fallback: DnsFallbackConfig,
    pub enable: bool,
    pub ipv6: bool,
    pub prefer_h3: bool,
    pub ipv6_timeout: Duration,
    pub cache_max_size: usize,
    pub cache_algorithm: DnsCacheAlgorithm,
    pub nameservers: Vec<DnsNameserver>,
    pub nameserver_policies: Vec<DnsNameserverPolicy>,
    pub default_nameservers: Vec<DnsNameserver>,
    pub proxy_nameservers: Vec<DnsNameserver>,
    pub proxy_policies: Vec<DnsNameserverPolicy>,
    pub direct_nameservers: Vec<DnsNameserver>,
    pub direct_follow_policy: bool,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub hosts: Vec<HostEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsCacheAlgorithm {
    #[default]
    Lru,
    Arc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub pattern: String,
    pub value: HostValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostValue {
    Addresses(Vec<IpAddr>),
    Alias(String),
    /// Interface addresses are captured during runtime preparation, never validation.
    Lan,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsAddress {
    Ip(IpAddr),
    Domain(String),
    Source(DnsSource),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsSource {
    System,
    Dhcp(Box<str>),
}

impl std::str::FromStr for DnsAddress {
    type Err = std::convert::Infallible;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Ok(value
            .parse()
            .map(Self::Ip)
            .unwrap_or_else(|_| Self::Domain(value.to_owned())))
    }
}

impl From<IpAddr> for DnsAddress {
    fn from(value: IpAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<Ipv4Addr> for DnsAddress {
    fn from(ip: Ipv4Addr) -> Self {
        Self::Ip(ip.into())
    }
}
impl From<Ipv6Addr> for DnsAddress {
    fn from(ip: Ipv6Addr) -> Self {
        Self::Ip(ip.into())
    }
}

impl std::fmt::Display for DnsAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Domain(host) => host.fmt(f),
            Self::Source(DnsSource::System) => f.write_str("system"),
            Self::Source(DnsSource::Dhcp(_)) => f.write_str("dhcp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsNameserver {
    pub transport: DnsTransport,
    pub address: DnsAddress,
    pub port: u16,
    pub route: DnsRoute,
    pub path: Option<String>,
    pub http_auth: Option<DnsHttpAuth>,
    pub options: DnsNameserverOptions,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsHttpAuth(pub(crate) Box<str>);

impl std::fmt::Debug for DnsHttpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DnsHttpAuth([redacted])")
    }
}

#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct DnsNameserverOptions {
    pub interface: Option<std::sync::Arc<str>>,
    pub ecs: Option<DnsEcs>,
    pub ecs_override: bool,
    pub disabled_types: Box<[u16]>,
    pub skip_cert_verify: bool,
    pub verification_name: Option<String>,
    pub disable_reuse: bool,
    pub force_h3: bool,
}

impl std::fmt::Debug for DnsNameserverOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsNameserverOptions")
            .field("has_interface", &self.interface.is_some())
            .field("ecs", &self.ecs.is_some())
            .field("ecs_override", &self.ecs_override)
            .field("disabled_type_count", &self.disabled_types.len())
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("explicit_name", &self.verification_name.is_some())
            .field("disable_reuse", &self.disable_reuse)
            .field("force_h3", &self.force_h3)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsEcs {
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameserverPolicy {
    pub selector: DnsPolicySelector,
    pub nameservers: Box<[DnsNameserver]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPolicySelector {
    GeoSite(Box<[String]>),
    Domains(Box<[String]>),
    RuleSets {
        names: Box<[String]>,
        sets: Vec<std::sync::Arc<RuleCollection>>,
    },
}

impl DnsNameserverPolicy {
    pub fn geosite_codes(&self) -> &[String] {
        match &self.selector {
            DnsPolicySelector::GeoSite(codes) => codes,
            DnsPolicySelector::Domains(_) | DnsPolicySelector::RuleSets { .. } => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsTransport {
    /// A local response with a Mihomo RCODE name, without network I/O.
    Rcode(u8),
    Udp,
    Tcp,
    Tls,
    Https,
    Http,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRoute {
    Direct,
    Reject,
    RejectDrop,
    Rules,
    Route(RouteTargetId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSpec {
    pub kind: RuleKind,
    pub action: RuleAction,
    pub no_resolve: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleControl {
    Pass,
    PassRule,
}

impl RuleControl {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::PassRule => "PASS-RULE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubRuleId(usize);

impl SubRuleId {
    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRuleProgram {
    pub name: String,
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRuleProgram {
    pub main: Vec<RuleSpec>,
    pub sub_rules: Vec<NamedRuleProgram>,
}

impl From<Vec<RuleSpec>> for RuntimeRuleProgram {
    fn from(main: Vec<RuleSpec>) -> Self {
        Self {
            main,
            sub_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    Flow {
        predicate: Box<RuleSpec>,
        control: RuleControl,
    },
    SubRule {
        predicate: Box<RuleSpec>,
        target: SubRuleId,
    },
    RuleSet {
        name: String,
        content: Option<std::sync::Arc<RuleCollection>>,
        source: bool,
    },
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainWildcard(String),
    DomainRegex(DomainRegex),
    And(Vec<RuleSpec>),
    Or(Vec<RuleSpec>),
    Not(Box<RuleSpec>),
    SrcIpCidr(IpCidr),
    SrcIpSuffix(IpSuffix),
    SrcPorts(Vec<PortRange>),
    GeoSite(String),
    GeoIp(String),
    SrcGeoIp(String),
    IpAsn(String),
    SrcIpAsn(String),
    InTypes(Vec<RuleInboundType>),
    InUsers(Vec<String>),
    Process(ProcessRule),
    Uid(Vec<UidRange>),
    InPorts(Vec<PortRange>),
    IpCidr(IpCidr),
    IpSuffix(IpSuffix),
    DstPorts(Vec<PortRange>),
    Network(Network),
    Match,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Route(RouteTargetId),
    Direct,
    Reject,
    RejectDrop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProxyId(usize);

impl ProxyId {
    #[must_use]
    pub const fn new(index: usize) -> Option<Self> {
        Some(Self(index))
    }

    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    fn from_index(index: usize) -> Self {
        Self(index)
    }
}

type ProxyIdsByTag = HashMap<String, ProxyId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProxyGroupId(usize);

impl ProxyGroupId {
    #[must_use]
    pub const fn new(index: usize) -> Option<Self> {
        Some(Self(index))
    }

    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    fn from_index(index: usize) -> Self {
        Self(index)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteTargetId {
    Proxy(ProxyId),
    Group(ProxyGroupId),
}

type RouteTargetsByName = HashMap<String, RouteTargetId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyGroupMemberTarget {
    Route(RouteTargetId),
    Direct,
    Reject,
    RejectDrop,
    Control(RuleControl),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyGroupMemberConfig {
    pub name: String,
    pub target: ProxyGroupMemberTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectProxyGroupConfig {
    pub kind: GroupKind,
    pub strategy: BalanceStrategy,
    pub hash_key: BalanceHashKey,
    pub health: HealthCheckConfig,
    pub tolerance: u16,
    pub max_failed_times: u32,
    pub name: String,
    pub members: Vec<ProxyGroupMemberConfig>,
    pub initial_member: usize,
    pub disable_udp: bool,
    pub hidden: bool,
    pub icon: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.prefix_len == 0
                    || u32::from(a) >> (32 - self.prefix_len)
                        == u32::from(b) >> (32 - self.prefix_len)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.prefix_len == 0
                    || u128::from(a) >> (128 - self.prefix_len)
                        == u128::from(b) >> (128 - self.prefix_len)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub egress: EgressOptions,
    pub ip_version: IpVersion,
    pub smux: Option<SingMuxConfig>,
    pub tag: String,
    pub dialer_proxy: Option<RouteTargetId>,
    pub udp: bool,
    pub protocol: ProxyProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocol {
    Direct,
    Dns,
    Reject,
    Masque(MasqueOutboundConfig),
    TrustTunnel(TrustTunnelOutboundConfig),
    Mieru(MieruOutboundConfig),
    Http(HttpOutboundConfig),
    WireGuard(WireGuardOutboundConfig),
    Tuic(TuicOutboundConfig),
    Hysteria2(Box<Hysteria2OutboundConfig>),
    Vmess(VmessOutboundConfig),
    Trojan(TrojanOutboundConfig),
    Vless(VlessOutboundConfig),
    Socks5(Socks5OutboundConfig),
    AnyTls(AnyTlsOutboundConfig),
    Shadowsocks(ShadowsocksOutboundConfig),
}

impl ProxyConfig {
    /// Functional route targets have no proxy-server endpoint.
    #[must_use]
    pub fn server_endpoint(&self) -> Option<(&str, u16)> {
        Some(match &self.protocol {
            ProxyProtocol::Direct | ProxyProtocol::Dns | ProxyProtocol::Reject => return None,
            ProxyProtocol::Masque(config) => (&config.address, config.port),
            ProxyProtocol::TrustTunnel(config) => (&config.address, config.port),
            ProxyProtocol::Mieru(config) => (&config.address, config.port),
            ProxyProtocol::WireGuard(config) => (&config.address, config.port),
            ProxyProtocol::Http(config) => (&config.address, config.port),
            ProxyProtocol::Tuic(config) => (&config.address, config.port),
            ProxyProtocol::Hysteria2(config) => (&config.address, config.port),
            ProxyProtocol::Vmess(config) => (&config.address, config.port),
            ProxyProtocol::Trojan(config) => (&config.address, config.port),
            ProxyProtocol::Vless(config) => (&config.address, config.port),
            ProxyProtocol::Socks5(config) => (&config.address, config.port),
            ProxyProtocol::AnyTls(config) => (&config.address, config.port),
            ProxyProtocol::Shadowsocks(config) => (&config.address, config.port),
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VlessOutboundConfig {
    pub address: String,
    pub port: u16,
    pub id: Uuid,
    pub encryption: VlessEncryption,
    pub flow: String,
    pub security: SecurityConfig,
    pub transport: VlessTransport,
    pub packet_encoding: VlessPacketEncoding,
    pub stream_options: VlessStreamOptions,
}

impl std::fmt::Debug for VlessOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessOutboundConfig")
            .finish_non_exhaustive()
    }
}

impl VlessOutboundConfig {
    pub fn xhttp(&self) -> Option<&XHttpConfig> {
        match &self.transport {
            VlessTransport::Xhttp(config) => Some(config),
            VlessTransport::Stream(_) => None,
        }
    }
    pub fn download(&self) -> Option<&XHttpDownloadConfig> {
        self.xhttp().and_then(|config| config.download.as_deref())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VlessTransport {
    Stream(StreamTransport),
    Xhttp(Box<XHttpConfig>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
pub enum VlessPacketEncoding {
    #[default]
    #[serde(rename = "xudp")]
    Xudp,
    #[serde(rename = "none")]
    Raw,
    #[serde(rename = "packetaddr", alias = "packet")]
    PacketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5OutboundConfig {
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: Option<TlsClientPolicy>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AnyTlsOutboundConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub server_name: String,
    pub security: SecurityConfig,
    pub session: AnyTlsSessionOptions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsClientPolicy {
    pub ech: Option<StaticEchConfig>,
    pub client_fingerprint: Option<ClientFingerprint>,
    pub alpn: Vec<Vec<u8>>,
    pub certificate: TlsCertificatePolicy,
    pub identity: Option<TlsIdentityPem>,
}

/// A version-pinned ClientHello profile, independent of certificate pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFingerprint {
    Chrome133,
    Firefox120,
    Safari16,
    Ios14,
}

// Only the immutable template value is process-shared. Selection precedes all
// node/REALITY/download-leg compatibility checks; Stop does not redraw it.
fn process_random_fingerprint() -> ClientFingerprint {
    static SELECTED: std::sync::OnceLock<ClientFingerprint> = std::sync::OnceLock::new();
    *SELECTED.get_or_init(|| weighted_fingerprint(rand::random_range(0..12)))
}

fn weighted_fingerprint(value: u8) -> ClientFingerprint {
    match value {
        0..=5 => ClientFingerprint::Chrome133,
        6..=8 => ClientFingerprint::Safari16,
        9..=10 => ClientFingerprint::Ios14,
        11 => ClientFingerprint::Firefox120,
        _ => unreachable!("fingerprint weight outside its bounded random range"),
    }
}

fn parse_client_fingerprint(value: Option<&str>) -> Result<Option<ClientFingerprint>> {
    match value {
        None | Some("" | "none") => Ok(None),
        Some(_) if !cfg!(feature = "tls-fingerprint") => {
            invalid("client-fingerprint is not compiled in")
        }
        Some("chrome") => Ok(Some(ClientFingerprint::Chrome133)),
        Some("firefox") => Ok(Some(ClientFingerprint::Firefox120)),
        Some("safari") => Ok(Some(ClientFingerprint::Safari16)),
        Some("ios") => Ok(Some(ClientFingerprint::Ios14)),
        Some("random") => Ok(Some(process_random_fingerprint())),
        Some(_) => invalid("unsupported client-fingerprint"),
    }
}

#[cfg(all(
    test,
    feature = "outbound-anytls",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-vless"
))]
mod fingerprint_tests;

impl std::fmt::Debug for AnyTlsOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsOutboundConfig")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum VlessEncryption {
    None,
    MlKem768X25519Plus(String),
}
impl std::fmt::Debug for VlessEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::MlKem768X25519Plus(_) => "MlKem768X25519Plus { .. }",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityConfig {
    None,
    Tls(TlsConfig),
    Reality(RealityConfig),
    Jls(JlsConfig),
    ShadowTls(ShadowTlsConfig),
}

impl SecurityConfig {
    #[must_use]
    pub fn as_tls(&self) -> Option<&TlsConfig> {
        match self {
            Self::Tls(config) => Some(config),
            _ => None,
        }
    }
    fn client_fingerprint(&self) -> Option<ClientFingerprint> {
        match self {
            Self::None => None,
            Self::Tls(config) => config.client_fingerprint,
            Self::Reality(config) => config.client_fingerprint,
            Self::Jls(config) => config.tls.client_fingerprint,
            Self::ShadowTls(config) => config.client_fingerprint,
        }
    }
    #[must_use]
    pub fn server_name(&self) -> &str {
        match self {
            Self::None => "",
            Self::Tls(config) => &config.server_name,
            Self::Reality(config) => &config.server_name,
            Self::Jls(config) => &config.tls.server_name,
            Self::ShadowTls(config) => &config.server_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub ech: Option<StaticEchConfig>,
    pub client_fingerprint: Option<ClientFingerprint>,
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    pub tls13_only: bool,
    pub required_alpn: Option<Vec<u8>>,
    pub certificate: TlsCertificatePolicy,
    pub identity: Option<TlsIdentityPem>,
}

/// Data-only certificate policy, also available in builds without TLS IO.
/// A matching leaf pin is the trust decision; a non-leaf pin still verifies
/// the chain and name. Explicit pin/name checks precede `skip_cert_verify`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TlsCertificatePolicy {
    pub verification_name: Option<String>,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<[u8; 32]>,
}

impl std::fmt::Debug for TlsCertificatePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCertificatePolicy")
            .field("explicit_name", &self.verification_name.is_some())
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("pinned", &self.fingerprint.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TlsIdentityPem {
    pub certificate: String,
    pub private_key: String,
}
impl std::fmt::Debug for TlsIdentityPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentityPem").finish_non_exhaustive()
    }
}

impl TlsConfig {
    pub fn xhttp(server_name: String) -> Self {
        Self {
            ech: None,
            client_fingerprint: None,
            server_name,
            alpn: vec![b"h2".to_vec()],
            tls13_only: true,
            required_alpn: Some(b"h2".to_vec()),
            certificate: Default::default(),
            identity: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub client_fingerprint: Option<ClientFingerprint>,
    pub support_x25519mlkem768: bool,
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub alpn: Vec<Vec<u8>>,
}

impl RealityConfig {
    pub(crate) fn validate_fingerprint(&self) -> Result<()> {
        if self.support_x25519mlkem768
            && !matches!(
                self.client_fingerprint,
                None | Some(ClientFingerprint::Chrome133)
            )
        {
            return invalid(
                "hybrid REALITY requires client-fingerprint chrome or no named fingerprint",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpConfig {
    pub path: String,
    pub host: String,
    pub mode: XHttpMode,
    pub http_version: XHttpVersion,
    pub headers: XHttpHeaders,
    pub request: std::sync::Arc<XHttpRequestOptions>,
    pub reuse: Option<std::sync::Arc<XHttpReuseConfig>>,
    pub download: Option<Box<XHttpDownloadConfig>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpDownloadConfig {
    pub address: String,
    pub port: u16,
    pub security: SecurityConfig,
    pub http_version: XHttpVersion,
    pub path: String,
    pub host: String,
    pub headers: XHttpHeaders,
    pub request: std::sync::Arc<XHttpRequestOptions>,
    pub reuse: Option<std::sync::Arc<XHttpReuseConfig>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMode {
    PacketUp,
    StreamOne,
    StreamUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundConfig {
    Tun(TunInboundConfig),
    Mixed(MixedInboundConfig),
}

impl InboundConfig {
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Tun(config) => &config.tag,
            Self::Mixed(config) => &config.tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunInboundConfig {
    pub tag: String,
    pub mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixedInboundConfig {
    pub access_rules: std::sync::Arc<ProxyAccessRules>,
    pub tag: String,
    pub port: u16,
    pub access: ProxyAccess,
    pub auth: Option<ProxyCredentials>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HttpInboundConfig {
    pub tag: String,
    pub port: u16,
    pub access: ProxyAccess,
    pub auth: Option<ProxyCredentials>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5InboundConfig {
    pub tag: String,
    pub port: u16,
    pub access: ProxyAccess,
    pub auth: Option<ProxyCredentials>,
}

impl std::fmt::Debug for HttpInboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpInboundConfig")
            .field("tag", &self.tag)
            .field("access", &self.access)
            .field("port", &self.port)
            .field("authenticated", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVoleConfig {
    #[serde(rename = "find-process-mode", default)]
    find_process_mode: FindProcessMode,
    #[serde(rename = "interface-name", default)]
    interface: String,
    #[serde(rename = "routing-mark", default)]
    routing_mark: i64,
    #[serde(default)]
    tls: TlsTrustConfig,
    #[serde(rename = "bind-address", default)]
    bind_address: Option<String>,
    #[serde(rename = "lan-allowed-ips", default)]
    lan_allowed_ips: Option<Vec<String>>,
    #[serde(rename = "lan-disallowed-ips", default)]
    lan_disallowed_ips: Vec<String>,
    #[serde(rename = "skip-auth-prefixes", default)]
    skip_auth_prefixes: Vec<String>,

    #[serde(rename = "tcp-concurrent", default)]
    tcp_concurrent: bool,
    #[serde(rename = "keep-alive-idle", default)]
    keep_alive_idle: i32,
    #[serde(rename = "keep-alive-interval", default)]
    keep_alive_interval: i32,
    #[serde(rename = "disable-keep-alive", default)]
    disable_keep_alive: bool,

    #[serde(rename = "unified-delay", default)]
    unified_delay: bool,
    #[serde(default)]
    profile: ProfileConfig,
    #[serde(default)]
    mode: Mode,
    #[serde(rename = "log-level", default)]
    log_level: LogLevel,
    #[serde(rename = "global-ua", default = "default_global_ua")]
    global_ua: String,
    #[serde(rename = "etag-support", default = "default_true")]
    etag_support: bool,
    #[serde(default)]
    hosts: std::collections::BTreeMap<String, RawPolicyNameservers>,
    #[serde(default = "default_true")]
    ipv6: bool,
    #[serde(
        rename = "geox-url",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    geox_url: Option<RawGeoDataUrls>,
    #[serde(rename = "geodata-mode", default)]
    geodata_mode: bool,
    #[serde(
        rename = "geo-auto-update",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    geo_auto_update: Option<bool>,
    #[serde(
        rename = "geo-update-interval",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    geo_update_interval: Option<u64>,
    #[serde(
        rename = "external-controller",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    external_controller: Option<String>,
    #[serde(
        rename = "external-controller-tls",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    external_controller_tls: Option<String>,
    #[serde(rename = "external-controller-cors", default)]
    external_controller_cors: ControllerCors,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    secret: Option<String>,
    #[serde(
        rename = "mixed-port",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    mixed_port: Option<u16>,
    #[serde(default, deserialize_with = "deserialize_present_credentials")]
    authentication: Option<Vec<String>>,
    #[serde(rename = "allow-lan", default)]
    allow_lan: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    tun: Option<RawTunConfig>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sniffer: Option<RawSnifferConfig>,
    #[serde(default, deserialize_with = "deserialize_non_null_vec")]
    proxies: Vec<RawOutbound>,
    #[serde(
        rename = "proxy-groups",
        default,
        deserialize_with = "deserialize_non_null_vec"
    )]
    proxy_groups: Vec<RawProxyGroup>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    dns: Option<RawDnsConfig>,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(rename = "sub-rules", default)]
    sub_rules: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxyGroup {
    #[serde(default)]
    strategy: BalanceStrategy,
    #[serde(rename = "hash-key", default)]
    hash_key: BalanceHashKey,
    #[serde(default)]
    url: String,
    #[serde(default)]
    interval: u64,
    #[serde(default)]
    timeout: u64,
    #[serde(default = "default_true")]
    lazy: bool,
    #[serde(
        rename = "expected-status",
        default,
        deserialize_with = "scalar::string_or_integer"
    )]
    expected_status: String,
    #[serde(default)]
    tolerance: u16,
    #[serde(rename = "max-failed-times", default)]
    max_failed_times: u32,

    #[serde(rename = "disable-udp", default)]
    disable_udp: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    icon: String,
    name: String,
    #[serde(rename = "type")]
    kind: GroupKind,
    proxies: Vec<String>,
    #[serde(rename = "default-selected", default)]
    default_selected: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGeoDataUrls {
    #[serde(default = "default_geoip_url")]
    geoip: String,
    #[serde(default = "default_mmdb_url")]
    mmdb: String,
    #[serde(default = "default_geosite_url")]
    geosite: String,
    #[serde(default = "default_asn_url")]
    asn: String,
}
impl std::fmt::Debug for RawGeoDataUrls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawGeoDataUrls").finish_non_exhaustive()
    }
}
fn default_global_ua() -> String {
    concat!("Vole/", env!("CARGO_PKG_VERSION")).into()
}
fn default_geoip_url() -> String {
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat".into()
}
fn default_mmdb_url() -> String {
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb".into()
}
fn default_geosite_url() -> String {
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat".into()
}
fn default_asn_url() -> String {
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb".into()
}
impl Default for RawGeoDataUrls {
    fn default() -> Self {
        Self {
            geoip: default_geoip_url(),
            mmdb: default_mmdb_url(),
            geosite: default_geosite_url(),
            asn: default_asn_url(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunConfig {
    #[serde(
        rename = "inet6-address",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    inet6_address: Option<Vec<String>>,
    #[serde(rename = "route-address", default)]
    route_address: Vec<String>,
    #[serde(rename = "route-exclude-address", default)]
    route_exclude_address: Vec<String>,
    #[serde(rename = "iproute2-table-index", default)]
    table_index: u32,
    #[serde(rename = "iproute2-rule-index", default)]
    rule_index: u32,
    #[serde(rename = "strict-route", default)]
    strict_route: bool,
    #[serde(rename = "include-uid", default)]
    include_uid: Vec<u32>,
    #[serde(rename = "include-uid-range", default)]
    include_uid_range: Vec<String>,
    #[serde(rename = "exclude-uid", default)]
    exclude_uid: Vec<u32>,
    #[serde(rename = "exclude-uid-range", default)]
    exclude_uid_range: Vec<String>,
    #[serde(rename = "exclude-src-port", default)]
    exclude_src_port: Vec<u16>,
    #[serde(rename = "exclude-src-port-range", default)]
    exclude_src_port_range: Vec<String>,
    #[serde(rename = "exclude-dst-port", default)]
    exclude_dst_port: Vec<u16>,
    #[serde(rename = "exclude-dst-port-range", default)]
    exclude_dst_port_range: Vec<String>,
    #[serde(rename = "auto-route", default)]
    auto_route: Option<bool>,
    #[serde(rename = "auto-detect-interface", default)]
    auto_detect_interface: Option<bool>,
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    mtu: u16,
    #[serde(rename = "file-descriptor", default)]
    file_descriptor: i32,
    #[serde(default)]
    device: String,
    #[serde(
        rename = "dns-hijack",
        default = "default_dns_hijack",
        deserialize_with = "deserialize_non_null_vec"
    )]
    dns_hijack: Vec<String>,
    #[serde(rename = "udp-timeout", default)]
    udp_timeout: u64,
}

impl RawTunConfig {
    fn normalize(self) -> Result<TunConfig> {
        let mtu = if self.mtu == 0 {
            default_mtu()
        } else {
            self.mtu
        };
        if mtu < 1_280 {
            return invalid("tun.mtu must be 0 or 1280..65535");
        }
        if self.file_descriptor < 0 {
            return invalid("tun.file-descriptor must be a nonnegative descriptor");
        }
        if self.device.chars().any(char::is_control) {
            return invalid("tun.device must not contain control characters");
        }
        let dns_hijack = self
            .dns_hijack
            .into_iter()
            .map(|target| {
                let endpoint = target
                    .split_once("://")
                    .map_or(target.as_str(), |(_, value)| value);
                let endpoint = endpoint.replacen("any", "0.0.0.0", 1);
                endpoint.parse::<SocketAddr>().map_err(|_| {
                    VoleError::InvalidConfig(
                        "tun.dns-hijack requires IP:port or any:port endpoints".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let udp_timeout = Duration::from_secs(if self.udp_timeout == 0 {
            300
        } else {
            self.udp_timeout
        });
        Ok(TunConfig {
            network: tun_network::RawTunNetworkConfig {
                inet6_address: self.inet6_address,
                route_address: self.route_address,
                route_exclude_address: self.route_exclude_address,
                table_index: self.table_index,
                rule_index: self.rule_index,
                strict_route: self.strict_route,
                include_uid: self.include_uid,
                include_uid_range: self.include_uid_range,
                exclude_uid: self.exclude_uid,
                exclude_uid_range: self.exclude_uid_range,
                exclude_src_port: self.exclude_src_port,
                exclude_src_port_range: self.exclude_src_port_range,
                exclude_dst_port: self.exclude_dst_port,
                exclude_dst_port_range: self.exclude_dst_port_range,
            }
            .normalize()?,
            auto_route: self.auto_route.unwrap_or(cfg!(target_os = "linux")),
            auto_detect_interface: self
                .auto_detect_interface
                .unwrap_or(cfg!(target_os = "linux")),
            enable: self.enable,
            mtu,
            file_descriptor: self.file_descriptor,
            device: self.device,
            dns_hijack,
            udp_timeout,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnifferConfig {
    #[serde(default)]
    enable: bool,
    #[serde(rename = "force-dns-mapping", default = "default_true")]
    force_dns_mapping: bool,
    #[serde(rename = "parse-pure-ip", default = "default_true")]
    parse_pure_ip: bool,
    #[serde(rename = "force-domain", default)]
    force_domain: Vec<String>,
    #[serde(rename = "skip-domain", default)]
    skip_domain: Vec<String>,
    #[serde(rename = "skip-src-address", default)]
    skip_src_address: Vec<String>,
    #[serde(rename = "skip-dst-address", default)]
    skip_dst_address: Vec<String>,
    #[serde(rename = "override-destination", default = "default_true")]
    override_destination: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sniff: Option<RawSniffConfig>,
}

#[derive(Debug, Default)]
struct RawSniffConfig {
    http: Option<Option<RawSniffProtocolConfig>>,
    tls: Option<Option<RawSniffProtocolConfig>>,
    quic: Option<Option<RawSniffProtocolConfig>>,
}
impl<'de> Deserialize<'de> for RawSniffConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let entries = serde_yaml_ng::Mapping::deserialize(deserializer)?;
        let mut result = Self::default();
        for (name, value) in entries {
            let name = name.as_str().ok_or_else(|| {
                serde::de::Error::custom("sniffer protocol name must be a string")
            })?;
            let field = match name.to_ascii_uppercase().as_str() {
                "HTTP" => &mut result.http,
                "TLS" => &mut result.tls,
                "QUIC" => &mut result.quic,
                _ => return Err(serde::de::Error::custom("unsupported sniffer protocol")),
            };
            *field = Some(serde_yaml_ng::from_value(value).map_err(serde::de::Error::custom)?);
        }
        Ok(result)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSniffProtocolConfig {
    #[serde(rename = "override-destination", default)]
    override_destination: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    ports: Option<Vec<RawSnifferPort>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSnifferPort {
    Integer(u64),
    String(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsConfig {
    #[serde(default)]
    fallback: Vec<String>,
    #[serde(rename = "fallback-filter", default)]
    fallback_filter: fallback::RawFallbackFilter,
    #[serde(rename = "fallback-lazy-query", default)]
    fallback_lazy_query: bool,
    #[serde(rename = "fake-ip-range", default = "fake_ip::default_fake_range")]
    fake_ip_range: String,
    #[serde(rename = "fake-ip-range6", default)]
    fake_ip_range6: String,
    #[serde(rename = "fake-ip-filter", default = "fake_ip::default_fake_filter")]
    fake_ip_filter: Vec<String>,
    #[serde(rename = "fake-ip-filter-mode", default)]
    fake_ip_filter_mode: FakeIpFilterMode,
    #[serde(rename = "fake-ip-ttl", default = "fake_ip::default_fake_ttl")]
    fake_ip_ttl: i64,
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    ipv6: bool,
    #[serde(rename = "prefer-h3", default)]
    prefer_h3: bool,
    #[serde(rename = "ipv6-timeout", default = "dns::default_ipv6_timeout")]
    ipv6_timeout: u64,
    #[serde(rename = "cache-max-size", default)]
    cache_max_size: usize,
    #[serde(rename = "cache-algorithm", default)]
    cache_algorithm: String,
    #[serde(default = "dns::default_nameservers")]
    nameserver: Vec<String>,
    #[serde(rename = "default-nameserver", default = "dns::default_bootstrap")]
    default_nameserver: Vec<String>,
    #[serde(rename = "proxy-server-nameserver", default)]
    proxy_nameserver: Vec<String>,
    #[serde(rename = "direct-nameserver", default)]
    direct_nameserver: Vec<String>,
    #[serde(rename = "direct-nameserver-follow-policy", default)]
    direct_follow_policy: bool,
    #[serde(rename = "use-hosts", default = "default_true")]
    use_hosts: bool,
    #[serde(rename = "use-system-hosts", default = "default_true")]
    use_system_hosts: bool,
    #[serde(rename = "respect-rules", default)]
    respect_rules: bool,
    #[serde(rename = "enhanced-mode", default = "dns::redir_host")]
    enhanced_mode: String,
    #[serde(
        rename = "nameserver-policy",
        default,
        deserialize_with = "deserialize_dns_nameserver_policies"
    )]
    nameserver_policies: Vec<RawDnsNameserverPolicy>,
    #[serde(
        rename = "proxy-server-nameserver-policy",
        default,
        deserialize_with = "deserialize_dns_nameserver_policies"
    )]
    proxy_policies: Vec<RawDnsNameserverPolicy>,
}

#[derive(Debug)]
struct RawDnsNameserverPolicy {
    selector: String,
    nameservers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawPolicyNameservers {
    One(String),
    Many(Vec<String>),
}

fn deserialize_dns_nameserver_policies<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<RawDnsNameserverPolicy>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedPoliciesVisitor;

    impl<'de> Visitor<'de> for OrderedPoliciesVisitor {
        type Value = Vec<RawDnsNameserverPolicy>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an ordered nameserver-policy mapping")
        }

        fn visit_map<A>(
            self,
            mut mapping: A,
        ) -> std::result::Result<Vec<RawDnsNameserverPolicy>, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut policies = Vec::with_capacity(mapping.size_hint().unwrap_or(0));
            while let Some((selector, nameservers)) =
                mapping.next_entry::<String, RawPolicyNameservers>()?
            {
                policies.push(RawDnsNameserverPolicy {
                    selector,
                    nameservers: match nameservers {
                        RawPolicyNameservers::One(nameserver) => vec![nameserver],
                        RawPolicyNameservers::Many(nameservers) => nameservers,
                    },
                });
            }
            Ok(policies)
        }
    }

    deserializer.deserialize_map(OrderedPoliciesVisitor)
}

#[derive(Debug)]
struct RawOutbound {
    egress: EgressOptions,
    ip_version: IpVersion,
    smux: Option<sing_mux::RawSingMux>,
    protocol: RawProtocol,
}
impl<'de> Deserialize<'de> for RawOutbound {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let mut value = serde_yaml_ng::Value::deserialize(deserializer)?;
        let mapping = value
            .as_mapping_mut()
            .ok_or_else(|| serde::de::Error::custom("proxy requires a mapping"))?;
        functional::validate_fields(mapping).map_err(serde::de::Error::custom)?;
        let interface = mapping
            .remove("interface-name")
            .map(serde_yaml_ng::from_value::<String>)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let mark = mapping
            .remove("routing-mark")
            .map(serde_yaml_ng::from_value::<i64>)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let egress = EgressOptions::normalize(interface, mark).map_err(serde::de::Error::custom)?;
        let ip_version = value
            .as_mapping_mut()
            .ok_or_else(|| serde::de::Error::custom("proxy requires a mapping"))?
            .remove("ip-version")
            .map(serde_yaml_ng::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let smux = value
            .as_mapping_mut()
            .expect("mapping checked")
            .remove("smux")
            .map(|value| {
                if !value.is_mapping() {
                    return Err("smux requires a mapping".to_owned());
                }
                serde_yaml_ng::from_value(value).map_err(|error| error.to_string())
            })
            .transpose()
            .map_err(serde::de::Error::custom)?;
        let protocol = serde_yaml_ng::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            egress,
            ip_version,
            smux,
            protocol,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
// This enum exists only while deserializing a configuration. Keeping the
// protocol fields inline avoids extra heap allocations in the startup path.
#[allow(clippy::large_enum_variant)]
enum RawProtocol {
    #[serde(rename = "direct")]
    Direct(functional::RawFunctional),
    #[serde(rename = "dns")]
    Dns(functional::RawFunctional),
    #[serde(rename = "reject")]
    Reject(functional::RawFunctional),
    #[serde(rename = "masque")]
    Masque(#[serde(deserialize_with = "masque::deserialize")] masque::RawMasque),
    #[serde(rename = "trusttunnel")]
    TrustTunnel(
        #[serde(deserialize_with = "trusttunnel::deserialize")] trusttunnel::RawTrustTunnel,
    ),
    #[serde(rename = "mieru")]
    Mieru(#[serde(deserialize_with = "mieru::deserialize")] mieru::RawMieru),
    #[serde(rename = "wireguard")]
    WireGuard(#[serde(deserialize_with = "wireguard::deserialize")] wireguard::RawWireGuard),
    #[serde(rename = "http")]
    Http(http_proxy::RawHttp),
    #[serde(rename = "tuic")]
    Tuic(#[serde(deserialize_with = "tuic::deserialize")] tuic::RawTuic),
    #[serde(rename = "hysteria2")]
    Hysteria2(hysteria2::RawHysteria2),
    #[serde(rename = "vmess")]
    Vmess(vmess::RawVmess),
    #[serde(rename = "trojan")]
    Trojan(trojan::RawTrojan),
    #[serde(rename = "ss")]
    Shadowsocks {
        name: String,
        server: String,
        port: u16,
        cipher: String,
        password: String,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        plugin: Option<String>,
        #[serde(
            rename = "plugin-opts",
            default,
            deserialize_with = "shadowsocks_plugin::deserialize"
        )]
        plugin_opts: Option<serde_yaml_ng::Value>,
        #[serde(
            rename = "client-fingerprint",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        client_fingerprint: Option<String>,
        #[serde(rename = "udp-over-tcp", default)]
        udp_over_tcp: bool,
        #[serde(
            rename = "udp-over-tcp-version",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        udp_over_tcp_version: Option<u8>,
        #[serde(default)]
        udp: bool,
        #[serde(
            rename = "dialer-proxy",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        dialer_proxy: Option<String>,
    },
    #[serde(rename = "vless")]
    Vless(vless::RawVless),
    #[serde(rename = "socks5")]
    Socks5 {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        udp: bool,
        #[serde(default)]
        tls: bool,
        #[serde(
            rename = "skip-cert-verify",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        skip_cert_verify: Option<bool>,
        #[serde(
            rename = "name-cert-verify",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        name_cert_verify: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        fingerprint: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        certificate: Option<String>,
        #[serde(
            rename = "private-key",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        private_key: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        username: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        password: Option<String>,
        #[serde(
            rename = "dialer-proxy",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        dialer_proxy: Option<String>,
    },
    #[serde(rename = "anytls")]
    AnyTls {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(rename = "idle-session-check-interval", default)]
        idle_session_check_interval: i64,
        #[serde(rename = "idle-session-timeout", default)]
        idle_session_timeout: i64,
        #[serde(rename = "min-idle-session", default)]
        min_idle_session: i64,
        #[serde(rename = "disable-reuse", default)]
        disable_reuse: bool,
        #[serde(rename = "client-metadata", default)]
        client_metadata: String,
        #[serde(default)]
        udp: bool,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        sni: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        alpn: Option<Vec<String>>,
        #[serde(
            rename = "skip-cert-verify",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        skip_cert_verify: Option<bool>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        fingerprint: Option<String>,
        #[serde(
            rename = "name-cert-verify",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        name_cert_verify: Option<String>,
        #[serde(default, deserialize_with = "deserialize_present_option")]
        certificate: Option<String>,
        #[serde(
            rename = "private-key",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        private_key: Option<String>,
        #[serde(
            rename = "client-fingerprint",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        client_fingerprint: Option<String>,
        #[serde(
            rename = "shadow-tls-opts",
            default,
            deserialize_with = "security::deserialize_shadow_tls"
        )]
        shadow_tls_opts: Option<security::RawShadowTlsMode>,
        #[serde(rename = "jls-opts", default, deserialize_with = "jls::deserialize")]
        jls_opts: Option<jls::RawJls>,
        #[serde(rename = "ech-opts", default, deserialize_with = "ech::deserialize")]
        ech_opts: Option<ech::RawEch>,
        #[serde(
            rename = "dialer-proxy",
            default,
            deserialize_with = "deserialize_present_option"
        )]
        dialer_proxy: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawXHttpSettings {
    #[serde(
        rename = "reuse-settings",
        default,
        deserialize_with = "deserialize_present_map"
    )]
    reuse_settings: Option<xhttp::RawReuseConfig>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    host: Option<String>,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default = "default_xhttp_mode")]
    mode: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(rename = "no-grpc-header", default)]
    no_grpc_header: bool,
    #[serde(
        rename = "x-padding-bytes",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    x_padding_bytes: Option<String>,
    #[serde(rename = "x-padding-obfs-mode", default)]
    x_padding_obfs_mode: bool,
    #[serde(
        rename = "x-padding-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    x_padding_key: Option<String>,
    #[serde(
        rename = "x-padding-header",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    x_padding_header: Option<String>,
    #[serde(
        rename = "x-padding-placement",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    x_padding_placement: Option<String>,
    #[serde(
        rename = "x-padding-method",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    x_padding_method: Option<String>,
    #[serde(
        rename = "uplink-http-method",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    uplink_http_method: Option<String>,
    #[serde(
        rename = "session-placement",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    session_placement: Option<String>,
    #[serde(
        rename = "session-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    session_key: Option<String>,
    #[serde(
        rename = "session-table",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    session_table: Option<String>,
    #[serde(
        rename = "session-length",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    session_length: Option<String>,
    #[serde(
        rename = "seq-placement",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    seq_placement: Option<String>,
    #[serde(
        rename = "seq-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    seq_key: Option<String>,
    #[serde(
        rename = "uplink-data-placement",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    uplink_data_placement: Option<String>,
    #[serde(
        rename = "uplink-data-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    uplink_data_key: Option<String>,
    #[serde(
        rename = "uplink-chunk-size",
        default,
        deserialize_with = "scalar::optional_string_or_integer"
    )]
    uplink_chunk_size: Option<String>,
    #[serde(
        rename = "sc-max-each-post-bytes",
        default,
        deserialize_with = "scalar::optional_string_or_integer"
    )]
    sc_max_each_post_bytes: Option<String>,
    #[serde(
        rename = "sc-min-posts-interval-ms",
        default,
        deserialize_with = "scalar::optional_string_or_integer"
    )]
    sc_min_posts_interval_ms: Option<String>,
    #[serde(
        rename = "download-settings",
        default,
        deserialize_with = "deserialize_present_map"
    )]
    download_settings: Option<RawXHttpDownloadSettings>,
}

impl Default for RawXHttpSettings {
    fn default() -> Self {
        Self {
            reuse_settings: None,
            host: None,
            path: default_path(),
            mode: default_xhttp_mode(),
            headers: Default::default(),
            no_grpc_header: false,
            x_padding_bytes: None,
            x_padding_obfs_mode: false,
            x_padding_key: None,
            x_padding_header: None,
            x_padding_placement: None,
            x_padding_method: None,
            uplink_http_method: None,
            session_placement: None,
            session_key: None,
            session_table: None,
            session_length: None,
            seq_placement: None,
            seq_key: None,
            uplink_data_placement: None,
            uplink_data_key: None,
            uplink_chunk_size: None,
            sc_max_each_post_bytes: None,
            sc_min_posts_interval_ms: None,
            download_settings: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawXHttpDownloadSettings {
    #[serde(
        rename = "client-fingerprint",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    client_fingerprint: Option<String>,
    #[serde(
        rename = "reuse-settings",
        default,
        deserialize_with = "deserialize_present_map"
    )]
    reuse_settings: Option<xhttp::RawReuseConfig>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    server: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    port: Option<u16>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    tls: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    servername: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(
        rename = "skip-cert-verify",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    skip_cert_verify: Option<bool>,
    #[serde(
        rename = "name-cert-verify",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    certificate: Option<String>,
    #[serde(
        rename = "private-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    private_key: Option<String>,
    #[serde(
        rename = "reality-opts",
        default,
        deserialize_with = "deserialize_present_map"
    )]
    reality_opts: Option<RawXHttpDownloadReality>,
    #[serde(
        rename = "shadow-tls-opts",
        default,
        deserialize_with = "security::deserialize_shadow_tls"
    )]
    shadow_tls_opts: Option<security::RawShadowTlsMode>,
    #[serde(rename = "jls-opts", default, deserialize_with = "jls::deserialize")]
    jls_opts: Option<jls::RawJls>,
    #[serde(rename = "ech-opts", default, deserialize_with = "ech::deserialize")]
    ech_opts: Option<ech::RawEch>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    path: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    host: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    headers: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawXHttpDownloadReality {
    #[serde(
        rename = "public-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    public_key: Option<String>,
    #[serde(
        rename = "short-id",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    short_id: Option<String>,
    #[serde(
        rename = "support-x25519mlkem768",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    support_x25519mlkem768: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRealitySettings {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "short-id", default)]
    short_id: String,
    #[serde(rename = "support-x25519mlkem768", default)]
    support_x25519mlkem768: bool,
}

#[derive(Debug)]
struct PendingProxyConfig {
    egress: EgressOptions,
    ip_version: IpVersion,
    smux: Option<SingMuxConfig>,
    tag: String,
    dialer_proxy: Option<String>,
    udp: bool,
    protocol: ProxyProtocol,
}

fn default_mtu() -> u16 {
    9_000
}

fn default_dns_hijack() -> Vec<String> {
    vec!["0.0.0.0:53".into()]
}

fn default_true() -> bool {
    true
}

fn default_path() -> String {
    "/".to_owned()
}

fn default_xhttp_mode() -> String {
    "auto".to_owned()
}

fn deserialize_present_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

// Derived structs also accept positional sequences. Configuration objects must
// remain named maps: in particular, [] must not silently select all defaults.
fn deserialize_present_map<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct NamedMap<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for NamedMap<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a named configuration map")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer
        .deserialize_map(NamedMap(std::marker::PhantomData))
        .map(Some)
}

fn deserialize_non_null_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("sequence must not be null"))
}

fn deserialize_present_credentials<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<String>>::deserialize(deserializer).map_err(|_| {
        serde::de::Error::custom("authentication must be a sequence of credential strings or null")
    })
}

impl Config {
    pub(crate) fn http_policy(&self) -> Option<std::sync::Arc<crate::http_processing::Policy>> {
        self.providers
            .as_ref()
            .and_then(|template| template.http_policy.clone())
    }
    pub(crate) fn set_http_config(&mut self, input: Option<&str>) -> Result<()> {
        let policy = crate::http_processing::Policy::compile_optional(input)?;
        let template = self
            .providers
            .as_mut()
            .ok_or_else(|| VoleError::InvalidConfig("configuration template is missing".into()))?;
        std::sync::Arc::make_mut(template).http_policy = policy;
        Ok(())
    }

    pub fn parse_yaml(input: &[u8]) -> Result<Self> {
        Self::parse_yaml_with_directory(input, None)
    }

    pub(crate) fn parse_yaml_with_directory(
        input: &[u8],
        directory: Option<&std::path::Path>,
    ) -> Result<Self> {
        let yaml = yaml::parse(input)?;
        let mut template = providers::ProviderTemplate::extract(yaml)?;
        template.identity_directory = directory.map(std::path::Path::to_path_buf);
        let template = std::sync::Arc::new(template);
        template.materialize(&providers::ProviderContents::new())
    }
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn take_runtime_rules(&mut self) -> RuntimeRuleProgram {
        match self.mode {
            Mode::Rule => RuntimeRuleProgram {
                main: std::mem::take(&mut self.rules),
                sub_rules: std::mem::take(&mut self.sub_rules),
            },
            Mode::Direct | Mode::Global => {
                let action = if self.mode == Mode::Direct {
                    RuleAction::Direct
                } else {
                    RuleAction::Route(RouteTargetId::Group(ProxyGroupId::from_index(
                        self.proxy_groups
                            .iter()
                            .position(|group| group.name == "GLOBAL")
                            .expect("GLOBAL group exists"),
                    )))
                };
                RuntimeRuleProgram::from(vec![RuleSpec {
                    kind: RuleKind::Match,
                    action,
                    no_resolve: false,
                }])
            }
        }
    }
}

impl RawVoleConfig {
    fn normalize(self) -> Result<Config> {
        if self.global_ua.len() > 1024
            || !self
                .global_ua
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return invalid("global-ua must be a bounded HTTP header value");
        }
        let geodata_update = normalize_geodata_update(
            self.geodata_mode,
            self.geox_url,
            self.geo_auto_update,
            self.geo_update_interval,
        )?;

        let mixed_port = self.mixed_port.filter(|port| *port != 0);
        let allow_lan = self.allow_lan && self.bind_address.as_deref() != Some("localhost");
        let bind_address = match self.bind_address.as_deref() {
            None | Some("" | "*" | "localhost") => None,
            Some(value) => Some(value.trim_matches(['[', ']']).parse::<IpAddr>().map_err(
                |_| {
                    VoleError::InvalidConfig(
                        "bind-address must be an IP address, localhost or *".into(),
                    )
                },
            )?),
        };
        let cidrs = |values: Vec<String>| {
            values
                .into_iter()
                .map(|value| parse_ip_cidr(&value, value.contains(':')))
                .collect::<Result<Vec<_>>>()
        };
        let access_rules = std::sync::Arc::new(ProxyAccessRules {
            allowed: self
                .lan_allowed_ips
                .map(cidrs)
                .transpose()?
                .unwrap_or_else(|| ProxyAccessRules::default().allowed),
            denied: cidrs(self.lan_disallowed_ips)?,
            skip_auth: cidrs(self.skip_auth_prefixes)?,
        });
        let authentication = normalize_proxy_authentication(self.authentication)?;

        let tun = self
            .tun
            .map_or_else(|| Ok(TunConfig::default()), RawTunConfig::normalize)?;
        let sniffer = self.sniffer.map_or_else(
            || Ok(SnifferConfig::disabled()),
            RawSnifferConfig::normalize,
        )?;

        let mut raw_groups = self.proxy_groups;
        let generated_global = !raw_groups.iter().any(|group| group.name == "GLOBAL");
        if generated_global {
            raw_groups.push(RawProxyGroup {
                strategy: BalanceStrategy::default(),
                hash_key: BalanceHashKey::default(),
                disable_udp: false,
                hidden: false,
                icon: String::new(),
                name: "GLOBAL".into(),
                kind: GroupKind::Select,
                url: String::new(),
                interval: 0,
                timeout: 0,
                lazy: true,
                expected_status: String::new(),
                tolerance: 0,
                max_failed_times: 0,
                proxies: vec!["DIRECT".into(), "REJECT".into()],
                default_selected: None,
            });
        }
        let (mut raw_proxy_groups, proxy_group_ids) =
            normalize_proxy_group_declarations(raw_groups)?;
        let (proxies, proxy_ids) =
            normalize_proxy_graph_with_groups(self.proxies, &proxy_group_ids)?;
        // The generated GLOBAL selector lists built-ins, nodes, then declared groups.
        if generated_global {
            let last = raw_proxy_groups.len() - 1;
            let mut members = vec!["DIRECT".into(), "REJECT".into()];
            members.extend(proxies.iter().map(|proxy| proxy.tag.clone()));
            members.extend(
                raw_proxy_groups[..last]
                    .iter()
                    .map(|group| group.name.clone()),
            );
            raw_proxy_groups[last].proxies = members;
        }
        let route_targets = collect_route_targets(&proxy_ids, &proxy_group_ids);
        let proxy_groups = normalize_proxy_groups(raw_proxy_groups, &route_targets)?;
        proxy_graph_order(&proxies, &proxy_groups)?;
        let mut external_controller =
            normalize_external_controller(self.external_controller, self.secret.clone())?;
        let tls_controller =
            normalize_external_controller(self.external_controller_tls, self.secret)?;
        if let Some(tls) = tls_controller {
            let controller = external_controller.get_or_insert_with(|| ExternalControllerConfig {
                http_enabled: false,
                ..tls.clone()
            });
            controller.tls_listen = Some(tls.listen);
        }
        if let Some(controller) = &mut external_controller {
            controller.cors = self.external_controller_cors;
            controller.server_tls = self.tls.server.clone();
        }

        let mut dns = self
            .dns
            .map_or_else(DnsConfig::disabled, |dns| dns.normalize(&route_targets))?;
        dns.ipv6 &= self.ipv6;
        dns.hosts = dns::normalize_hosts(self.hosts)?;
        let (rules, sub_rules) =
            normalize_rule_program(self.rules, self.sub_rules, &route_targets)?;
        drop(proxy_ids);
        drop(route_targets);

        let mut inbounds = Vec::with_capacity(2);
        if let Some(port) = mixed_port {
            inbounds.push(InboundConfig::Mixed(MixedInboundConfig {
                access_rules,
                tag: "mixed-in".to_owned(),
                port,
                access: ProxyAccess {
                    bind_address,
                    allow_lan,
                    ipv6: self.ipv6,
                },
                auth: authentication,
            }));
        }
        if tun.enable {
            inbounds.push(InboundConfig::Tun(TunInboundConfig {
                tag: "tun-in".to_owned(),
                mtu: tun.mtu,
            }));
        }

        Ok(Config {
            egress: EgressOptions::normalize(self.interface, self.routing_mark)?,
            tls: self.tls,
            ipv6: self.ipv6,
            proxies,
            proxy_groups,
            mode: self.mode,
            log_level: self.log_level,
            global_ua: self.global_ua,
            etag_support: self.etag_support,
            unified_delay: self.unified_delay,
            find_process_mode: self.find_process_mode,
            connections: ConnectionSettings {
                tcp_concurrent: self.tcp_concurrent,
                keep_alive_idle: self.keep_alive_idle,
                keep_alive_interval: self.keep_alive_interval,
                disable_keep_alive: self.disable_keep_alive,
            },
            profile: self.profile,
            geodata_update,
            external_controller,
            inbounds,
            mixed_port,
            tun,
            sniffer,
            dns,
            rules,
            sub_rules,
            providers: None,
            provider_members: HashMap::new(),
        })
    }
}

fn normalize_external_controller(
    listen: Option<String>,
    secret: Option<String>,
) -> Result<Option<ExternalControllerConfig>> {
    let Some(listen) = listen.filter(|listen| !listen.is_empty()) else {
        return Ok(None);
    };
    // Mihomo's tcp preResolve accepts literal IPs, localhost and an empty host
    // without consulting DNS.
    let listen = if let Ok(address) = listen.parse::<SocketAddr>() {
        address
    } else {
        let address = listen
            .strip_prefix("localhost:")
            .map(|port| (IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            .or_else(|| {
                listen
                    .strip_prefix(':')
                    .map(|port| (IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
            });
        let Some((host, port)) = address else {
            return invalid(
                "external-controller requires an IP, localhost or empty host and a numeric port",
            );
        };
        let port = port.parse::<u16>().map_err(|_| {
            VoleError::InvalidConfig("external-controller port must be between 0 and 65535".into())
        })?;
        SocketAddr::new(host, port)
    };
    Ok(Some(ExternalControllerConfig {
        listen,
        secret: secret.filter(|secret| !secret.is_empty()),
        ..ExternalControllerConfig::default()
    }))
}

fn normalize_geodata_update(
    geodata_mode: bool,
    urls: Option<RawGeoDataUrls>,
    auto_update: Option<bool>,
    interval_hours: Option<u64>,
) -> Result<Option<GeoDataUpdateConfig>> {
    let urls = urls.unwrap_or_default();
    let interval_hours = interval_hours.unwrap_or(GEO_UPDATE_INTERVAL_HOURS);
    if interval_hours.checked_mul(3600).is_none() {
        return invalid("geo-update-interval is too large");
    }
    Ok(Some(GeoDataUpdateConfig {
        geodata_mode,
        urls: GeoDataUrls {
            geoip: normalize_geox_url(urls.geoip, "geox-url.geoip")?,
            mmdb: normalize_geox_url(urls.mmdb, "geox-url.mmdb")?,
            geosite: normalize_geox_url(urls.geosite, "geox-url.geosite")?,
            asn: normalize_geox_url(urls.asn, "geox-url.asn")?,
        },
        auto_update: auto_update.unwrap_or(false),
        interval_hours,
    }))
}

fn normalize_geox_url(raw: String, field: &str) -> Result<String> {
    if raw.len() > MAX_GEOX_URL_BYTES {
        return invalid(format!(
            "{field} exceeds the {MAX_GEOX_URL_BYTES}-byte limit"
        ));
    }
    let url = Url::parse(&raw)
        .map_err(|error| VoleError::InvalidConfig(format!("{field} is invalid: {error}")))?;
    if url.scheme() != "https" {
        return invalid(format!("{field} must use HTTPS"));
    }
    crate::resource::http::parse_url(&raw, &Default::default())
        .map_err(|_| VoleError::InvalidConfig(format!("{field} has invalid URL authentication")))?;
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return invalid(format!("{field} must contain a domain host"));
    }
    if url.fragment().is_some() {
        return invalid(format!("{field} must not contain a fragment"));
    }
    Ok(raw)
}

impl RawSnifferConfig {
    fn normalize(self) -> Result<SnifferConfig> {
        let sniff = self.sniff.unwrap_or_default();
        let override_for = |raw: &Option<Option<RawSniffProtocolConfig>>| {
            raw.as_ref()
                .and_then(Option::as_ref)
                .and_then(|raw| raw.override_destination)
                .unwrap_or(self.override_destination)
        };
        let http_override = override_for(&sniff.http);
        let tls_override = override_for(&sniff.tls);
        let quic_override = override_for(&sniff.quic);
        Ok(SnifferConfig {
            enable: self.enable,
            force_dns_mapping: self.force_dns_mapping,
            parse_pure_ip: self.parse_pure_ip,
            force_domain: sniffer::domains(self.force_domain)?,
            skip_domain: sniffer::domains(self.skip_domain)?,
            skip_src_address: sniffer::addresses(self.skip_src_address)?,
            skip_dst_address: sniffer::addresses(self.skip_dst_address)?,
            http_override,
            tls_override,
            quic_override,
            http_ports: normalize_sniffer_protocol(sniff.http, "HTTP")?.unwrap_or_default(),
            tls_ports: normalize_sniffer_protocol(sniff.tls, "TLS")?.unwrap_or_default(),
            quic_ports: normalize_sniffer_protocol(sniff.quic, "QUIC")?.unwrap_or_default(),
        })
    }
}

fn normalize_sniffer_protocol(
    raw: Option<Option<RawSniffProtocolConfig>>,
    protocol: &str,
) -> Result<Option<Box<[PortRange]>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.unwrap_or_default();
    let ranges = match raw.ports {
        None => vec![PortRange {
            start: 0,
            end: u16::MAX,
        }],
        Some(items) => {
            if items.is_empty() {
                return Ok(Some(
                    vec![PortRange {
                        start: 0,
                        end: u16::MAX,
                    }]
                    .into_boxed_slice(),
                ));
            }
            if items.len() > MAX_SNIFFER_PORT_ITEMS {
                return invalid(format!(
                    "sniffer.sniff.{protocol}.ports exceeds the {MAX_SNIFFER_PORT_ITEMS}-item limit"
                ));
            }
            items
                .into_iter()
                .map(|item| parse_sniffer_port(item, protocol))
                .collect::<Result<Vec<_>>>()?
        }
    };
    Ok(Some(merge_port_ranges(ranges).into_boxed_slice()))
}

fn parse_sniffer_port(item: RawSnifferPort, protocol: &str) -> Result<PortRange> {
    match item {
        RawSnifferPort::Integer(port) => {
            let port = parse_sniffer_port_number(port, protocol)?;
            Ok(PortRange {
                start: port,
                end: port,
            })
        }
        RawSnifferPort::String(value) => {
            if let Some((start, end)) = value.split_once('-') {
                if start.is_empty() || end.is_empty() || end.contains('-') {
                    return invalid(format!(
                        "sniffer.sniff.{protocol}.ports contains invalid range `{value}`"
                    ));
                }
                let start = parse_sniffer_port_string(start, protocol)?;
                let end = parse_sniffer_port_string(end, protocol)?;
                if start > end {
                    return invalid(format!(
                        "sniffer.sniff.{protocol}.ports range start must not exceed its end"
                    ));
                }
                Ok(PortRange { start, end })
            } else {
                let port = parse_sniffer_port_string(&value, protocol)?;
                Ok(PortRange {
                    start: port,
                    end: port,
                })
            }
        }
    }
}

fn parse_sniffer_port_string(value: &str, protocol: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid(format!(
            "sniffer.sniff.{protocol}.ports contains invalid port `{value}`"
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        VoleError::InvalidConfig(format!(
            "sniffer.sniff.{protocol}.ports contains invalid port `{value}`"
        ))
    })?;
    parse_sniffer_port_number(parsed, protocol)
}

fn parse_sniffer_port_number(value: u64, protocol: &str) -> Result<u16> {
    u16::try_from(value).ok().ok_or_else(|| {
        VoleError::InvalidConfig(format!(
            "sniffer.sniff.{protocol}.ports values must be between 1 and 65535"
        ))
    })
}

fn merge_port_ranges(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end.saturating_add(1)
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn port_ranges_contain(ranges: &[PortRange], port: u16) -> bool {
    ranges
        .binary_search_by(|range| {
            if port < range.start {
                std::cmp::Ordering::Greater
            } else if port > range.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn normalize_proxy_authentication(
    authentication: Option<Vec<String>>,
) -> Result<Option<ProxyCredentials>> {
    match authentication {
        None => Ok(None),
        Some(entries) if entries.is_empty() => Ok(None),
        Some(entries) => entries
            .into_iter()
            .map(|credential| {
                let (username, password) = credential.split_once(':').ok_or_else(|| {
                    VoleError::InvalidConfig("authentication entry must use user:password".into())
                })?;
                ProxyCredentials::new(username, password)
                    .map_err(|error| VoleError::InvalidConfig(error.to_string()))
            })
            .collect::<Result<Vec<_>>>()
            .map(|values| Some(ProxyCredentials::multiple(values))),
    }
}

#[cfg(feature = "invoke")]
fn normalize_proxy_graph(
    raw_proxies: Vec<RawOutbound>,
) -> Result<(Vec<ProxyConfig>, ProxyIdsByTag)> {
    let (proxies, ids) = normalize_proxy_graph_with_groups(raw_proxies, &HashMap::new())?;
    proxy_graph_order(&proxies, &[])?;
    Ok((proxies, ids))
}

fn normalize_proxy_graph_with_groups(
    raw_proxies: Vec<RawOutbound>,
    proxy_group_ids: &HashMap<String, ProxyGroupId>,
) -> Result<(Vec<ProxyConfig>, ProxyIdsByTag)> {
    let pending = raw_proxies
        .into_iter()
        .map(RawOutbound::normalize)
        .collect::<Result<Vec<_>>>()?;
    let mut proxy_ids = ProxyIdsByTag::with_capacity(pending.len());
    for (index, proxy) in pending.iter().enumerate() {
        if proxy_group_ids.contains_key(&proxy.tag) {
            return invalid(format!(
                "route target name `{}` is used by both a proxy and a proxy group",
                proxy.tag
            ));
        }
        if proxy_ids
            .insert(proxy.tag.clone(), ProxyId::from_index(index))
            .is_some()
        {
            return invalid(format!("duplicate proxy name `{}`", proxy.tag));
        }
    }
    let dialer_proxies = pending
        .iter()
        .map(|proxy| {
            proxy
                .dialer_proxy
                .as_deref()
                .filter(|tag| !matches!(*tag, "DIRECT" | "COMPATIBLE"))
                .map(|tag| {
                    if let Some(id) = proxy_group_ids.get(tag) {
                        return Ok(RouteTargetId::Group(*id));
                    }
                    proxy_ids.get(tag).copied().map(RouteTargetId::Proxy).ok_or_else(|| {
                        VoleError::InvalidConfig(format!(
                            "proxy `{}` dialer-proxy `{tag}` does not reference DIRECT or a configured proxy or group name",
                            proxy.tag
                        ))
                    })
                })
                .transpose()
        })
        .collect::<Result<Vec<_>>>()?;
    let proxies = pending
        .into_iter()
        .zip(dialer_proxies)
        .map(|(proxy, dialer_proxy)| ProxyConfig {
            egress: proxy.egress,
            ip_version: proxy.ip_version,
            smux: proxy.smux,
            tag: proxy.tag,
            dialer_proxy,
            udp: proxy.udp,
            protocol: proxy.protocol,
        })
        .collect();
    Ok((proxies, proxy_ids))
}

fn normalize_proxy_group_declarations(
    raw_groups: Vec<RawProxyGroup>,
) -> Result<(Vec<RawProxyGroup>, HashMap<String, ProxyGroupId>)> {
    let mut group_ids = HashMap::with_capacity(raw_groups.len());
    for (index, group) in raw_groups.iter().enumerate() {
        validate_route_target_definition_name(&group.name, "proxy group name")?;
        if group.proxies.is_empty() {
            return invalid(format!(
                "proxy group `{}` proxies must contain at least 1 entry",
                group.name
            ));
        }
        if group_ids
            .insert(group.name.clone(), ProxyGroupId::from_index(index))
            .is_some()
        {
            return invalid(format!("duplicate proxy group name `{}`", group.name));
        }
    }
    Ok((raw_groups, group_ids))
}

fn collect_route_targets(
    proxy_ids: &ProxyIdsByTag,
    proxy_group_ids: &HashMap<String, ProxyGroupId>,
) -> RouteTargetsByName {
    let mut targets = RouteTargetsByName::with_capacity(proxy_ids.len() + proxy_group_ids.len());
    targets.extend(
        proxy_ids
            .iter()
            .map(|(name, id)| (name.clone(), RouteTargetId::Proxy(*id))),
    );
    targets.extend(
        proxy_group_ids
            .iter()
            .map(|(name, id)| (name.clone(), RouteTargetId::Group(*id))),
    );
    targets
}

fn normalize_proxy_groups(
    raw_groups: Vec<RawProxyGroup>,
    route_targets: &RouteTargetsByName,
) -> Result<Vec<SelectProxyGroupConfig>> {
    let groups = raw_groups
        .into_iter()
        .map(|group| {
            if group.hash_key != BalanceHashKey::Default
                && (group.kind != GroupKind::LoadBalance || group.strategy == BalanceStrategy::RoundRobin)
            {
                return invalid("hash-key requires consistent-hashing or sticky-sessions load-balance");
            }
            let members = group
                .proxies
                .into_iter()
                .map(|name| {
                    validate_route_target_name(&name, "proxy group member")?;
                    let target = match name.as_str() {
                        "DIRECT" | "COMPATIBLE" => ProxyGroupMemberTarget::Direct,
                        "REJECT" => ProxyGroupMemberTarget::Reject,
                        "REJECT-DROP" => ProxyGroupMemberTarget::RejectDrop,
                        "PASS" => ProxyGroupMemberTarget::Control(RuleControl::Pass),
                        "PASS-RULE" => ProxyGroupMemberTarget::Control(RuleControl::PassRule),
                        _ => route_targets
                            .get(&name)
                            .copied()
                            .map(ProxyGroupMemberTarget::Route)
                            .ok_or_else(|| {
                                VoleError::InvalidConfig(format!(
                                    "proxy group `{}` member `{name}` does not reference a configured proxy, proxy group, DIRECT, COMPATIBLE, REJECT, REJECT-DROP, PASS, or PASS-RULE",
                                    group.name
                                ))
                            })?,
                    };
                    Ok(ProxyGroupMemberConfig { name, target })
                })
                .collect::<Result<Vec<_>>>()?;
            let initial_member = group
                .default_selected
                .and_then(|default| members.iter().position(|member| member.name == default))
                .unwrap_or(0);
            let health = HealthCheckConfig {
                enable: true,
                url: if group.url.is_empty() { "https://www.gstatic.com/generate_204".into() } else { group.url },
                interval: if group.interval == 0 && group.kind != GroupKind::Select { 300 } else { group.interval },
                timeout: if group.timeout == 0 { 5000 } else { group.timeout },
                lazy: group.lazy,
                expected_status: group.expected_status,
            };
            health.validate()?;
            Ok(SelectProxyGroupConfig {
                kind: group.kind, strategy: group.strategy, hash_key: group.hash_key, health, tolerance: group.tolerance,
                max_failed_times: if group.max_failed_times == 0 { 5 } else { group.max_failed_times },
                name: group.name,
                members,
                initial_member,
                disable_udp: group.disable_udp,
                hidden: group.hidden,
                icon: group.icon,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(groups)
}

/// Validates the complete node/member graph, including unselected members, and
/// returns dependency-first construction order. Iterative O(V + E) traversal
/// keeps configuration-sized chains off the native stack.
pub(crate) fn proxy_graph_order(
    proxies: &[ProxyConfig],
    groups: &[SelectProxyGroupConfig],
) -> Result<Vec<RouteTargetId>> {
    let count = proxies.len() + groups.len();
    let index_of = |target| match target {
        RouteTargetId::Proxy(id) if id.index() < proxies.len() => Ok(id.index()),
        RouteTargetId::Group(id) if id.index() < groups.len() => Ok(proxies.len() + id.index()),
        _ => invalid("proxy graph references an unknown node or group"),
    };
    let mut dependency_counts = vec![0_usize; count];
    let mut dependents = vec![Vec::<usize>::new(); count];
    let mut add_dependency = |dependent: usize, target| -> Result<()> {
        dependency_counts[dependent] += 1;
        dependents[index_of(target)?].push(dependent);
        Ok(())
    };
    for (index, proxy) in proxies.iter().enumerate() {
        if let Some(parent) = proxy.dialer_proxy {
            add_dependency(index, parent)?;
        }
    }
    for (group_index, group) in groups.iter().enumerate() {
        for member in &group.members {
            if let ProxyGroupMemberTarget::Route(target) = member.target {
                add_dependency(proxies.len() + group_index, target)?;
            }
        }
    }

    let mut ready = dependency_counts
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut order = Vec::with_capacity(count);
    while let Some(index) = ready.pop_front() {
        order.push(if index < proxies.len() {
            RouteTargetId::Proxy(ProxyId::from_index(index))
        } else {
            RouteTargetId::Group(ProxyGroupId::from_index(index - proxies.len()))
        });
        for &dependent in &dependents[index] {
            dependency_counts[dependent] -= 1;
            if dependency_counts[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }
    if order.len() != count {
        return invalid(
            "proxy graph contains a circular dialer-proxy or circular member dependency",
        );
    }
    Ok(order)
}

impl RawOutbound {
    fn normalize(self) -> Result<PendingProxyConfig> {
        let (tag, dialer_proxy, udp, protocol) = match self.protocol {
            RawProtocol::Direct(raw) => raw.normalize(ProxyProtocol::Direct)?,
            RawProtocol::Dns(raw) => raw.normalize(ProxyProtocol::Dns)?,
            RawProtocol::Reject(raw) => raw.normalize(ProxyProtocol::Reject)?,
            RawProtocol::Masque(raw) => raw.normalize()?,
            RawProtocol::TrustTunnel(raw) => raw.normalize()?,
            RawProtocol::Mieru(raw) => raw.normalize()?,
            RawProtocol::WireGuard(raw) => raw.normalize()?,
            RawProtocol::Http(raw) => raw.normalize()?,
            RawProtocol::Hysteria2(raw) => raw.normalize()?,
            RawProtocol::Tuic(raw) => raw.normalize()?,
            RawProtocol::Vmess(raw) => raw.normalize()?,
            RawProtocol::Trojan(raw) => raw.normalize()?,
            RawProtocol::Shadowsocks {
                name,
                server,
                port,
                cipher,
                password,
                plugin,
                plugin_opts,
                client_fingerprint,
                udp_over_tcp,
                udp_over_tcp_version,
                udp,
                dialer_proxy,
            } => {
                let mut config = shadowsocks::normalize(server, port, cipher, password)?;
                config.plugin =
                    shadowsocks_plugin::normalize(plugin, plugin_opts, client_fingerprint, port)?;
                if udp_over_tcp && !cfg!(feature = "outbound-shadowsocks") {
                    return invalid("Shadowsocks UoT support is not enabled in this build");
                }
                if udp_over_tcp && !udp {
                    return invalid("Shadowsocks udp-over-tcp requires udp: true");
                }
                if udp_over_tcp_version.is_some_and(|version| !udp_over_tcp || version != 2) {
                    return invalid("Shadowsocks udp-over-tcp-version requires enabled UoT v2");
                }
                config.udp_over_tcp = udp_over_tcp;
                (name, dialer_proxy, udp, ProxyProtocol::Shadowsocks(config))
            }
            RawProtocol::Vless(raw) => raw.normalize()?,
            RawProtocol::Socks5 {
                name,
                server,
                port,
                udp,
                tls,
                skip_cert_verify,
                name_cert_verify,
                fingerprint,
                certificate,
                private_key,
                username,
                password,
                dialer_proxy,
            } => {
                let mut config = normalize_socks5(server, port, username, password)?;
                if !tls
                    && (skip_cert_verify.is_some()
                        || name_cert_verify.is_some()
                        || fingerprint.is_some()
                        || certificate.is_some()
                        || private_key.is_some())
                {
                    return invalid("SOCKS5 TLS options require tls: true");
                }
                if tls {
                    config.tls = Some(TlsClientPolicy {
                        certificate: TlsCertificatePolicy {
                            skip_cert_verify: skip_cert_verify.unwrap_or(false),
                            fingerprint: normalize_certificate_fingerprint(fingerprint.as_deref())?,
                            verification_name: normalize_verification_name(name_cert_verify)?,
                        },
                        identity: normalize_client_identity(certificate, private_key)?,
                        ..Default::default()
                    });
                }
                (name, dialer_proxy, udp, ProxyProtocol::Socks5(config))
            }
            RawProtocol::AnyTls {
                name,
                server,
                port,
                password,
                idle_session_check_interval,
                idle_session_timeout,
                min_idle_session,
                disable_reuse,
                client_metadata,
                udp,
                sni,
                alpn,
                skip_cert_verify,
                fingerprint,
                name_cert_verify,
                certificate,
                private_key,
                client_fingerprint,
                ech_opts,
                shadow_tls_opts,
                jls_opts,
                dialer_proxy,
            } => {
                let certificate_options = skip_cert_verify.is_some()
                    || fingerprint.is_some()
                    || name_cert_verify.is_some()
                    || certificate.is_some()
                    || private_key.is_some();
                let mut config = normalize_anytls(
                    server,
                    port,
                    password,
                    sni,
                    alpn,
                    skip_cert_verify.unwrap_or(false),
                    fingerprint,
                )?;
                let SecurityConfig::Tls(mut tls) = config.security else {
                    unreachable!()
                };
                tls.certificate.verification_name = normalize_verification_name(name_cert_verify)?;
                tls.identity = normalize_client_identity(certificate, private_key)?;
                tls.client_fingerprint = parse_client_fingerprint(client_fingerprint.as_deref())?;
                config.session = AnyTlsSessionOptions::normalize(
                    idle_session_check_interval,
                    idle_session_timeout,
                    min_idle_session,
                    disable_reuse,
                    client_metadata,
                )?;
                tls.ech = ech_opts
                    .map(|raw| raw.normalize(tls.client_fingerprint.is_some()))
                    .transpose()?
                    .flatten();
                if tls.ech.is_some() && config.server_name.parse::<IpAddr>().is_ok() {
                    return invalid("AnyTLS ECH requires DNS sni");
                }
                config.security = security::RawSecurityModes {
                    reality: None,
                    jls: jls_opts,
                    shadow_tls: shadow_tls_opts,
                }
                .normalize(tls, certificate_options)?;

                (name, dialer_proxy, udp, ProxyProtocol::AnyTls(config))
            }
        };
        let smux = self
            .smux
            .map(sing_mux::RawSingMux::normalize)
            .transpose()?
            .flatten();
        if smux.is_some()
            && matches!(&protocol, ProxyProtocol::Vless(node) if node.flow == "xtls-rprx-vision")
        {
            return invalid("VLESS Vision cannot use sing-mux");
        }
        let udp = udp || smux.as_ref().is_some_and(|options| !options.only_tcp);
        validate_route_target_definition_name(&tag, "proxy name")?;
        let dialer_proxy = dialer_proxy.filter(|tag| !tag.is_empty());
        if let Some(dialer_proxy) = &dialer_proxy {
            validate_route_target_name(dialer_proxy, "dialer-proxy")?;
        }
        Ok(PendingProxyConfig {
            egress: self.egress,
            ip_version: self.ip_version,
            smux,
            tag,
            dialer_proxy,
            udp,
            protocol,
        })
    }
}

impl RawRealitySettings {
    fn normalize(self, server_name: String) -> Result<RealityConfig> {
        let decoded = URL_SAFE_NO_PAD
            .decode(self.public_key.as_bytes())
            .map_err(|_| VoleError::InvalidConfig("invalid REALITY public-key".to_owned()))?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|_| {
            VoleError::InvalidConfig("invalid REALITY public-key length".to_owned())
        })?;
        if URL_SAFE_NO_PAD.encode(public_key) != self.public_key {
            return invalid("REALITY public-key must use canonical unpadded base64url");
        }

        if self.short_id.len() > 16 || !self.short_id.len().is_multiple_of(2) {
            return invalid("REALITY short-id must be at most 16 even-numbered hex characters");
        }
        let mut short_id = Vec::with_capacity(self.short_id.len() / 2);
        for pair in self.short_id.as_bytes().as_chunks::<2>().0 {
            let pair = std::str::from_utf8(pair).expect("hex input is UTF-8");
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| VoleError::InvalidConfig("invalid REALITY short-id".to_owned()))?;
            short_id.push(byte);
        }

        Ok(RealityConfig {
            client_fingerprint: None,
            support_x25519mlkem768: self.support_x25519mlkem768,
            server_name,
            public_key,
            short_id,
            alpn: vec![b"h2".to_vec()],
        })
    }
}

fn normalize_socks5(
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
) -> Result<Socks5OutboundConfig> {
    validate_host(&server, "SOCKS5 server")?;
    validate_port(port, "SOCKS5")?;
    match (&username, &password) {
        (None, None) => {}
        (Some(username), Some(password)) => {
            for (name, value) in [("username", username), ("password", password)] {
                if !(1..=u8::MAX as usize).contains(&value.len()) {
                    return invalid(format!(
                        "SOCKS5 {name} must contain between 1 and 255 UTF-8 bytes"
                    ));
                }
            }
        }
        _ => {
            return invalid("SOCKS5 username and password must be provided together");
        }
    }
    Ok(Socks5OutboundConfig {
        address: server,
        port,
        username,
        password,
        tls: None,
    })
}

fn normalize_anytls(
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
) -> Result<AnyTlsOutboundConfig> {
    validate_host(&server, "AnyTLS server")?;
    validate_port(port, "AnyTLS")?;
    if !(1..=MAX_ANYTLS_PASSWORD_BYTES).contains(&password.len()) {
        return invalid(format!(
            "AnyTLS password must contain between 1 and {MAX_ANYTLS_PASSWORD_BYTES} UTF-8 bytes"
        ));
    }
    let server_name = sni
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| server.clone());
    validate_host(&server_name, "AnyTLS sni")?;
    let alpn = alpn
        .unwrap_or_default()
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    if alpn
        .iter()
        .any(|protocol| protocol.is_empty() || protocol.len() > 255)
        || alpn
            .iter()
            .map(|protocol| protocol.len() + 1)
            .sum::<usize>()
            > 65_533
    {
        return invalid(
            "AnyTLS alpn names must be 1..255 bytes and the encoded list at most 65533 bytes",
        );
    }
    let fingerprint = normalize_certificate_fingerprint(fingerprint.as_deref())?;
    Ok(AnyTlsOutboundConfig {
        address: server,
        port,
        password,
        server_name: server_name.clone(),
        session: AnyTlsSessionOptions::default(),
        security: SecurityConfig::Tls(TlsConfig {
            server_name,
            tls13_only: false,
            required_alpn: None,
            ech: None,
            identity: None,
            client_fingerprint: None,
            alpn,
            certificate: TlsCertificatePolicy {
                skip_cert_verify,
                fingerprint,
                ..Default::default()
            },
        }),
    })
}

fn normalize_certificate_fingerprint(fingerprint: Option<&str>) -> Result<Option<[u8; 32]>> {
    fingerprint
        .filter(|value| !value.is_empty())
        .map(vless::parse_pin)
        .transpose()
}

fn normalize_verification_name(name: Option<String>) -> Result<Option<String>> {
    let name = name.filter(|name| !name.is_empty());
    if let Some(name) = &name {
        validate_host(name, "TLS certificate verification name")?;
    }
    Ok(name)
}

fn normalize_client_identity(
    certificate: Option<String>,
    private_key: Option<String>,
) -> Result<Option<TlsIdentityPem>> {
    match (
        certificate.filter(|pem| !pem.is_empty()),
        private_key.filter(|pem| !pem.is_empty()),
    ) {
        (None, None) => Ok(None),
        (Some(certificate), Some(private_key)) => {
            crate::security::TlsClientIdentity::from_pem(&certificate, &private_key)
                .map_err(|_| VoleError::InvalidConfig("invalid TLS client identity".into()))?;
            Ok(Some(TlsIdentityPem {
                certificate,
                private_key,
            }))
        }
        _ => invalid("TLS certificate and private-key must be provided together"),
    }
}

impl RawXHttpSettings {
    fn normalize(
        self,
        default_address: &str,
        default_port: u16,
        default_explicit_server_name: Option<&str>,
        default_host: &str,
        security: &SecurityConfig,
        http_version: XHttpVersion,
    ) -> Result<XHttpConfig> {
        if http_version == XHttpVersion::Http3 && !matches!(security, SecurityConfig::Tls(_)) {
            return invalid("XHTTP HTTP/3 requires standard TLS");
        }
        let headers = XHttpHeaders::normalize(self.headers.clone())?;
        let has_download = self.download_settings.is_some();
        let mode = match self.mode.as_str() {
            "" | "auto" if matches!(security, SecurityConfig::Reality(_)) && has_download => {
                XHttpMode::StreamUp
            }
            "" | "auto" if matches!(security, SecurityConfig::Reality(_)) => XHttpMode::StreamOne,
            "" | "auto" | "packet-up" => XHttpMode::PacketUp,
            "stream-one" if !has_download => XHttpMode::StreamOne,
            "stream-one" => {
                return invalid("xhttp mode `stream-one` cannot be used with download-settings");
            }
            "stream-up" => XHttpMode::StreamUp,
            _ => return invalid("XHTTP mode must be auto, packet-up, stream-up, or stream-one"),
        };
        let request = std::sync::Arc::new(XHttpRequestOptions::normalize(&self, &headers, mode)?);
        let reuse = self
            .reuse_settings
            .map(|raw| raw.normalize(http_version))
            .transpose()?
            .map(std::sync::Arc::new);
        let Self {
            host,
            path,
            download_settings,
            ..
        } = self;
        let host = host.filter(|value| !value.is_empty());
        let path = if path.is_empty() { "/".into() } else { path };
        if path.len() > 2_048
            || !path.starts_with('/')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return invalid(
                "xhttp-opts.path must be a valid path/query starting with `/` and at most 2048 bytes",
            );
        }
        let mut download = download_settings
            .map(|settings| {
                settings.normalize(XHttpDownloadDefaults {
                    address: default_address,
                    port: default_port,
                    explicit_server_name: default_explicit_server_name,
                    security,
                    http_version,
                    path: &path,
                    explicit_host: host.as_deref(),
                    headers: &headers,
                    reuse: &reuse,
                })
            })
            .transpose()?
            .map(Box::new);
        let host = host.unwrap_or_else(|| {
            default_host.parse::<std::net::Ipv6Addr>().map_or_else(
                |_| default_host.to_owned(),
                |address| format!("[{address}]"),
            )
        });
        if host.is_empty()
            || host.len() > 253
            || host.contains('@')
            || host.parse::<http::uri::Authority>().is_err()
        {
            return invalid("xhttp-opts.host must be a valid HTTP authority");
        }

        if let Some(download) = &mut download {
            request.validate_headers(&download.headers, &download.path)?;
            download.request = request.clone();
        }
        Ok(XHttpConfig {
            path,
            host,
            mode,
            http_version,
            headers,
            request,
            download,
            reuse,
        })
    }
}

struct XHttpDownloadDefaults<'a> {
    reuse: &'a Option<std::sync::Arc<XHttpReuseConfig>>,
    address: &'a str,
    port: u16,
    explicit_server_name: Option<&'a str>,
    security: &'a SecurityConfig,
    http_version: XHttpVersion,
    path: &'a str,
    explicit_host: Option<&'a str>,
    headers: &'a XHttpHeaders,
}

impl RawXHttpDownloadSettings {
    fn normalize(self, defaults: XHttpDownloadDefaults<'_>) -> Result<XHttpDownloadConfig> {
        let XHttpDownloadDefaults {
            reuse: default_reuse,
            address: default_address,
            port: default_port,
            explicit_server_name: default_explicit_server_name,
            security: default_security,
            http_version: default_http_version,
            path: default_path,
            explicit_host: default_explicit_host,
            headers: default_headers,
        } = defaults;
        let Self {
            server,
            port,
            tls,
            servername,
            alpn,
            skip_cert_verify,
            name_cert_verify,
            fingerprint,
            client_fingerprint,
            certificate,
            private_key,
            reality_opts,
            jls_opts,
            shadow_tls_opts,
            ech_opts,
            path,
            host,
            headers,
            reuse_settings,
        } = self;
        let headers = headers
            .map(XHttpHeaders::normalize)
            .transpose()?
            .unwrap_or_else(|| default_headers.clone());

        let http_version = alpn
            .as_deref()
            .map(XHttpVersion::from_alpn)
            .transpose()?
            .unwrap_or(default_http_version);
        let tls = tls.unwrap_or(!matches!(default_security, SecurityConfig::None));
        let client_fingerprint = match client_fingerprint {
            Some(value) => parse_client_fingerprint(Some(&value))?,
            None => default_security.client_fingerprint(),
        };
        if client_fingerprint.is_some() && (!tls || http_version == XHttpVersion::Http3) {
            return invalid(
                "XHTTP download client-fingerprint requires TCP TLS; clear the inherited profile before selecting plaintext or HTTP/3",
            );
        }
        let reuse = match reuse_settings {
            Some(raw) => Some(std::sync::Arc::new(raw.normalize(http_version)?)),
            None => default_reuse.clone(),
        };
        if http_version == XHttpVersion::Http1
            && reuse
                .as_ref()
                .is_some_and(|value| value.keep_alive_seconds != 0)
        {
            return invalid("XHTTP HTTP/1 download cannot inherit a keepalive period override");
        }

        let address = server.unwrap_or_else(|| default_address.to_owned());
        validate_host(&address, "XHTTP download server")?;
        let port = port.unwrap_or(default_port);
        validate_port(port, "XHTTP download")?;

        let server_name = servername
            .or_else(|| default_explicit_server_name.map(str::to_owned))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| address.clone());
        validate_host(&server_name, "XHTTP download servername")?;
        let host = host
            .or_else(|| default_explicit_host.map(str::to_owned))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                server_name
                    .parse::<std::net::Ipv6Addr>()
                    .map_or_else(|_| server_name.clone(), |address| format!("[{address}]"))
            });
        if host.is_empty()
            || host.len() > 253
            || host.contains('@')
            || host.parse::<http::uri::Authority>().is_err()
        {
            return invalid("xhttp-opts.download-settings.host must be a valid HTTP authority");
        }
        let reality = match reality_opts {
            None => match default_security {
                SecurityConfig::Reality(config) => {
                    let mut config = config.clone();
                    config.server_name = server_name.clone();
                    Some(config)
                }
                _ => None,
            },
            Some(RawXHttpDownloadReality {
                public_key: None,
                short_id: None,
                support_x25519mlkem768: None,
            }) => None,
            Some(RawXHttpDownloadReality {
                public_key: Some(public_key),
                short_id,
                support_x25519mlkem768,
            }) => Some(
                RawRealitySettings {
                    public_key,
                    short_id: short_id.unwrap_or_default(),
                    support_x25519mlkem768: support_x25519mlkem768.unwrap_or(false),
                }
                .normalize(server_name.clone())?,
            ),
            Some(_) => return invalid("XHTTP download REALITY replacement requires public-key"),
        };
        // Resolve inherited leaf policies before choosing the final security
        // mode. A mode switch must not silently erase a pin or client identity.
        let mut config = match default_security {
            SecurityConfig::Tls(config) => config.clone(),
            SecurityConfig::Jls(config) => config.tls.clone(),
            SecurityConfig::ShadowTls(config) => config.tls_config(),
            _ => TlsConfig::xhttp(server_name.clone()),
        };
        config.server_name = server_name;
        config.client_fingerprint = client_fingerprint;
        config.alpn = vec![http_version.alpn().to_vec()];
        config.required_alpn = Some(http_version.alpn().to_vec());
        if let Some(raw) = ech_opts {
            config.ech = raw.normalize(config.client_fingerprint.is_some())?;
        }
        config.ech = config
            .ech
            .as_ref()
            .map(|ech| ech.for_backend(config.client_fingerprint.is_some()))
            .transpose()?;
        if config.ech.is_some() && config.server_name.parse::<IpAddr>().is_ok() {
            return invalid("XHTTP download ECH requires a DNS servername");
        }
        if let Some(skip) = skip_cert_verify {
            config.certificate.skip_cert_verify = skip;
        }
        if let Some(name) = name_cert_verify {
            config.certificate.verification_name = if name.is_empty() {
                None
            } else {
                validate_host(&name, "XHTTP download certificate verification name")?;
                Some(name)
            };
        }
        if let Some(pin) = fingerprint {
            config.certificate.fingerprint = if pin.is_empty() {
                None
            } else {
                Some(vless::parse_pin(&pin)?)
            };
        }
        match (certificate, private_key) {
            (None, None) => {}
            (Some(certificate), Some(private_key))
                if certificate.is_empty() && private_key.is_empty() =>
            {
                config.identity = None
            }
            (Some(certificate), Some(private_key)) => {
                vless::validate_client_identity(&certificate, &private_key)?;
                config.identity = Some(TlsIdentityPem {
                    certificate,
                    private_key,
                });
            }
            _ => {
                return invalid(
                    "XHTTP download certificate and private-key must be replaced or cleared together",
                );
            }
        }
        let certificate_policy = config.certificate.skip_cert_verify
            || config.certificate.verification_name.is_some()
            || config.certificate.fingerprint.is_some()
            || config.identity.is_some();
        let jls = match jls_opts {
            Some(raw) if raw.is_empty() => None,
            Some(raw) => Some(raw.normalize(config.clone())?),
            None => match default_security {
                SecurityConfig::Jls(config) => Some(config.clone()),
                _ => None,
            },
        };
        let shadow_tls = match shadow_tls_opts {
            Some(raw) if raw.is_empty() => None,
            Some(raw) => Some(raw.normalize(config.clone())?),
            None => match default_security {
                SecurityConfig::ShadowTls(config) => Some(config.clone()),
                _ => None,
            },
        };
        if usize::from(reality.is_some())
            + usize::from(jls.is_some())
            + usize::from(shadow_tls.is_some())
            > 1
        {
            return invalid("XHTTP download transport identities are mutually exclusive");
        }
        if config.ech.is_some()
            && (reality.is_some() || jls.is_some() || shadow_tls.is_some() || !tls)
        {
            return invalid(
                "XHTTP download ECH requires standard TLS; clear inherited ECH before changing security mode",
            );
        }
        if (reality.is_some() || jls.is_some() || !tls) && certificate_policy {
            return invalid(
                "XHTTP download must explicitly clear inherited certificate policy before changing security mode",
            );
        }
        let security = if let Some(mut reality) = reality {
            if !tls {
                return invalid("XHTTP download REALITY requires TLS");
            }
            reality.alpn = vec![http_version.alpn().to_vec()];
            reality.client_fingerprint = client_fingerprint;
            reality.validate_fingerprint()?;
            SecurityConfig::Reality(reality)
        } else if let Some(mut jls) = jls {
            if !tls {
                return invalid("XHTTP download JLS requires TLS");
            }
            jls.tls = config;
            jls.validate()?;
            SecurityConfig::Jls(jls)
        } else if let Some(mut shadow_tls) = shadow_tls {
            if !tls {
                return invalid("XHTTP download ShadowTLS requires TLS");
            }
            shadow_tls.server_name = config.server_name;
            shadow_tls.client_fingerprint = config.client_fingerprint;
            shadow_tls.alpn = config.alpn;
            shadow_tls.required_alpn = config.required_alpn;
            shadow_tls.certificate = config.certificate;
            shadow_tls.identity = config.identity;
            shadow_tls.validate()?;
            SecurityConfig::ShadowTls(shadow_tls)
        } else if tls {
            SecurityConfig::Tls(config)
        } else {
            SecurityConfig::None
        };
        if http_version == XHttpVersion::Http3 && !matches!(security, SecurityConfig::Tls(_)) {
            return invalid("XHTTP HTTP/3 download requires standard TLS");
        }

        let path = path
            .map(|path| if path.is_empty() { "/".into() } else { path })
            .unwrap_or_else(|| default_path.to_owned());
        if path.len() > 2_048
            || !path.starts_with('/')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return invalid(
                "xhttp-opts.download-settings.path must be a valid path/query starting with `/` and at most 2048 bytes",
            );
        }
        Ok(XHttpDownloadConfig {
            address,
            port,
            security,
            http_version,
            path,
            host,
            headers,
            request: Default::default(),
            reuse,
        })
    }
}

fn normalize_dns_nameserver_policies(
    raw_policies: Vec<RawDnsNameserverPolicy>,
    route_targets: &RouteTargetsByName,
    default_route: DnsRoute,
) -> Result<Vec<DnsNameserverPolicy>> {
    let mut normalized = Vec::with_capacity(raw_policies.len());
    for raw_policy in raw_policies {
        let selector = normalize_dns_policy_selector(&raw_policy.selector)?;

        if raw_policy.nameservers.is_empty() {
            return invalid(format!(
                "dns.nameserver-policy `{}` must contain at least one nameserver",
                raw_policy.selector
            ));
        }
        let nameservers = raw_policy
            .nameservers
            .iter()
            .map(|nameserver| parse_dns_nameserver(nameserver, route_targets, default_route))
            .collect::<Result<Vec<_>>>()?;
        normalized.push(DnsNameserverPolicy {
            selector,
            nameservers: nameservers.into_boxed_slice(),
        });
    }
    Ok(normalized)
}

fn normalize_dns_policy_selector(input: &str) -> Result<DnsPolicySelector> {
    let lower = input.to_lowercase();
    if let Some(selector) = lower.strip_prefix("geosite:") {
        let codes = selector
            .split(',')
            .map(|code| {
                if code.is_empty() || trim_ascii_whitespace(code) != code {
                    return invalid("DNS policy GeoSite selectors must be non-empty without surrounding whitespace");
                }
                normalize_geo_code(code, "dns.nameserver-policy GeoSite")
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(DnsPolicySelector::GeoSite(codes.into_boxed_slice()));
    }
    if let Some(selector) = input.strip_prefix("rule-set:") {
        let names = selector.split(',').map(str::to_owned).collect::<Vec<_>>();
        if names.iter().any(|name| name.is_empty()) {
            return invalid("DNS policy rule-set requires provider names");
        }
        return Ok(DnsPolicySelector::RuleSets {
            names: names.into_boxed_slice(),
            sets: Vec::new(),
        });
    }
    let domains = lower
        .split(',')
        .map(|domain| {
            if domain.is_empty() || domain.ends_with('.') || domain.trim() != domain {
                return invalid("invalid DNS policy domain pattern");
            }
            for (index, label) in domain.split('.').enumerate() {
                if (label.is_empty() && index != 0)
                    || (label.contains('+') && (index != 0 || label != "+" || domain == "+"))
                    || (label.contains('*') && label != "*")
                {
                    return invalid("invalid DNS policy domain pattern");
                }
            }
            Ok(domain.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DnsPolicySelector::Domains(domains.into_boxed_slice()))
}

use dns::parse_dns_nameserver;

fn normalize_rule_program(
    main: Vec<String>,
    definitions: std::collections::BTreeMap<String, Vec<String>>,
    route_targets: &RouteTargetsByName,
) -> Result<(Vec<RuleSpec>, Vec<NamedRuleProgram>)> {
    let mut count = main.len();
    let mut bytes = 0_usize;
    let mut ids = HashMap::with_capacity(definitions.len());
    for (index, (name, rules)) in definitions.iter().enumerate() {
        if name.is_empty() {
            return invalid("sub-rule name must not be empty");
        }
        count = count
            .checked_add(rules.len())
            .ok_or_else(|| VoleError::InvalidConfig("rules count overflowed".into()))?;
        bytes = bytes
            .checked_add(name.len())
            .ok_or_else(|| VoleError::InvalidConfig("rules byte length overflowed".into()))?;
        ids.insert(name.clone(), SubRuleId(index));
    }
    if count > MAX_RULES {
        return invalid(format!("rules exceeds the {MAX_RULES}-entry limit"));
    }
    if bytes > MAX_RULES_TOTAL_BYTES {
        return invalid(format!(
            "rules exceeds the {MAX_RULES_TOTAL_BYTES}-byte cumulative limit"
        ));
    }
    let mut normalize = |rules: Vec<String>| -> Result<Vec<RuleSpec>> {
        rules
            .into_iter()
            .map(|rule| {
                if rule.len() > MAX_RULE_BYTES {
                    return invalid(format!(
                        "rule exceeds the {MAX_RULE_BYTES}-byte per-entry limit"
                    ));
                }
                bytes = bytes.checked_add(rule.len()).ok_or_else(|| {
                    VoleError::InvalidConfig("rules byte length overflowed".into())
                })?;
                if bytes > MAX_RULES_TOTAL_BYTES {
                    return invalid(format!(
                        "rules exceeds the {MAX_RULES_TOTAL_BYTES}-byte cumulative limit"
                    ));
                }
                rules::parse_program_rule(&rule, route_targets, &ids)
            })
            .collect()
    };
    let main = normalize(main)?;
    let sub_rules = definitions
        .into_iter()
        .map(|(name, rules)| {
            Ok(NamedRuleProgram {
                name,
                rules: normalize(rules)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    rules::validate_subrule_calls(&main, &sub_rules)?;
    Ok((main, sub_rules))
}

fn trim_ascii_whitespace(input: &str) -> &str {
    input.trim_matches(|character: char| character.is_ascii_whitespace())
}

fn parse_rule_action(action: &str, route_targets: &RouteTargetsByName) -> Result<RuleAction> {
    match action {
        "DIRECT" | "COMPATIBLE" => Ok(RuleAction::Direct),
        "REJECT" => Ok(RuleAction::Reject),
        "REJECT-DROP" => Ok(RuleAction::RejectDrop),
        tag => route_targets
            .get(tag)
            .copied()
            .map(RuleAction::Route)
            .ok_or_else(|| {
                VoleError::InvalidConfig(format!(
                    "rule target must be exactly DIRECT, COMPATIBLE, REJECT, REJECT-DROP, or a configured proxy or proxy group name; found `{action}`"
                ))
            }),
    }
}

fn normalize_rule_domain(input: &str, rule_type: &str) -> Result<String> {
    let input = input.strip_suffix('.').unwrap_or(input);
    crate::routing::normalize_domain_name(input)
        .map_err(|_| VoleError::InvalidConfig(format!("invalid {rule_type} domain")))
}

fn normalize_rule_keyword(input: &str) -> Result<String> {
    if input.is_empty()
        || input.len() > 253
        || !input.is_ascii()
        || input.bytes().any(|byte| byte.is_ascii_control())
    {
        return invalid("invalid DOMAIN-KEYWORD value");
    }
    Ok(input.to_ascii_lowercase())
}

fn normalize_geo_code(input: &str, rule_type: &str) -> Result<String> {
    let kind = if rule_type == "GEOIP" {
        crate::geodata::GeoDataKind::GeoIp
    } else {
        crate::geodata::GeoDataKind::GeoSite
    };
    crate::geodata::normalize_selector(kind, input)
        .map_err(|_| VoleError::InvalidConfig(format!("invalid {rule_type} selector")))
}

fn parse_ip_cidr(input: &str, require_v6: bool) -> Result<IpCidr> {
    let (address, prefix) = input
        .split_once('/')
        .ok_or_else(|| VoleError::InvalidConfig("CIDR must include a prefix length".to_owned()))?;
    if prefix.contains('/') {
        return invalid("CIDR must contain exactly one `/`");
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| VoleError::InvalidConfig(format!("invalid CIDR address `{address}`")))?;
    let prefix_len = prefix
        .parse::<u8>()
        .map_err(|_| VoleError::InvalidConfig(format!("invalid CIDR prefix `{prefix}`")))?;

    let network = match (require_v6, address) {
        (false, IpAddr::V4(address)) if prefix_len <= 32 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_len))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        (true, IpAddr::V6(address)) if prefix_len <= 128 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix_len))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
        (false, IpAddr::V6(_)) => return invalid("IP-CIDR requires an IPv4 network"),
        (true, IpAddr::V4(_)) => return invalid("IP-CIDR6 requires an IPv6 network"),
        (false, IpAddr::V4(_)) => return invalid("IPv4 CIDR prefix must be between 0 and 32"),
        (true, IpAddr::V6(_)) => return invalid("IPv6 CIDR prefix must be between 0 and 128"),
    };
    Ok(IpCidr {
        network,
        prefix_len,
    })
}

fn parse_port_ranges(input: &str) -> Result<Vec<PortRange>> {
    let input = input.trim();
    if input.split('/').count() > 28 {
        return invalid("port rule exceeds 28 ranges");
    }
    let mut ranges = Vec::new();
    for item in input.split('/').filter(|item| !item.is_empty()) {
        let item = item.trim();
        if item.is_empty() {
            ranges.push(PortRange { start: 0, end: 0 });
            continue;
        }
        let (start, end) = item.split_once('-').unwrap_or((item, item));
        let parse = |value: &str| -> Result<u16> {
            let value = value.trim_matches(['[', ']', ' ']);
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return invalid("invalid rule port");
            }
            value
                .parse()
                .map_err(|_| VoleError::InvalidConfig("invalid rule port".into()))
        };
        let (start, end) = (parse(start)?, parse(end)?);
        ranges.push(PortRange {
            start: start.min(end),
            end: start.max(end),
        });
    }
    if ranges.is_empty() {
        return invalid("port rule requires at least one range");
    }
    Ok(ranges)
}

fn parse_network(input: &str) -> Result<Network> {
    if input.eq_ignore_ascii_case("tcp") {
        Ok(Network::Tcp)
    } else if input.eq_ignore_ascii_case("udp") {
        Ok(Network::Udp)
    } else {
        invalid("NETWORK value must be TCP or UDP")
    }
}

pub(crate) fn validate_route_target_name(name: &str, field: &str) -> Result<()> {
    if name.is_empty() {
        return invalid(format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_route_target_definition_name(name: &str, field: &str) -> Result<()> {
    validate_route_target_name(name, field)?;
    if matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE"
    ) {
        return invalid(format!("{field} `{name}` is reserved"));
    }
    Ok(())
}

fn validate_host(host: &str, field: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        return invalid(format!("invalid {field}"));
    }
    if IpAddr::from_str(host).is_ok() {
        return Ok(());
    }
    if !host.is_ascii()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return invalid(format!("invalid {field}"));
    }
    Ok(())
}

fn validate_port(port: u16, kind: &str) -> Result<()> {
    if port == 0 {
        return invalid(format!("{kind} port must be between 1 and 65535"));
    }
    Ok(())
}

fn parse_standard_uuid(input: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(input)
        .map_err(|_| VoleError::InvalidConfig("invalid VLESS settings.id UUID".to_owned()))?;
    if id.hyphenated().to_string() != input.to_ascii_lowercase() {
        return invalid("VLESS settings.id must use standard hyphenated UUID form");
    }
    Ok(id)
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(VoleError::InvalidConfig(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_and_global_group_work_without_a_final_match() {
        use crate::routing::{RoutingContext, RuleEvaluation, RuleSet};
        let destination = crate::session::Destination::Ip("192.0.2.1:443".parse().unwrap());
        let context = RoutingContext::new(Network::Tcp, &destination).unwrap();
        for mode in ["rule", "DIRECT", "global"] {
            let mut config = Config::parse_yaml(
                format!("mixed-port: 1080\nmode: {mode}\nlog-level: Warning\n").as_bytes(),
            )
            .unwrap();
            assert_eq!(config.log_level, LogLevel::Warning);
            assert_eq!(config.proxy_groups[0].name, "GLOBAL");
            assert_eq!(config.proxy_groups[0].members[0].name, "DIRECT");
            let expected = if config.mode == Mode::Global {
                RuleAction::Route(RouteTargetId::Group(ProxyGroupId::from_index(0)))
            } else {
                RuleAction::Direct
            };
            let RuleEvaluation::Matched(result) = RuleSet::compile(config.take_runtime_rules())
                .unwrap()
                .evaluate(&context)
            else {
                panic!("mode must select an action")
            };
            assert_eq!(result.action, expected);
        }
        let config = Config::parse_yaml(b"mixed-port: 1080\nproxy-groups: [{name: GLOBAL, type: select, proxies: [REJECT, DIRECT]}]\n").unwrap();
        assert_eq!(config.proxy_groups.len(), 1);
        assert_eq!(config.proxy_groups[0].members[0].name, "REJECT");
    }

    #[test]
    fn ingress_source_params_types_users_ports_and_hash_schema() {
        let mut config = Config::parse_yaml(
            br#"
mixed-port: 1080
proxy-groups: [{name: pool, type: load-balance, proxies: [DIRECT], hash-key: in-user}]
rules:
  - SRC-GEOIP,CN,DIRECT
  - GEOIP,CN,DIRECT,no-resolve,src
  - GEOIP,CN,DIRECT,src,no-resolve
  - IP-CIDR,2001:db8::/32,DIRECT,src
  - IP-CIDR6,192.0.2.0/24,DIRECT,src
  - IN-TYPE,HTTP / https / SOCKS / TUN / INNER,DIRECT
  - IN-USER, Alice / Bob ,DIRECT
  - IN-PORT,0/1081-1080//65535,DIRECT
"#,
        )
        .unwrap();
        assert_eq!(config.proxy_groups[0].hash_key, BalanceHashKey::InUser);
        assert!(config.rules[..5].iter().all(|rule| rule.no_resolve));
        assert_eq!(config.rules[0].kind, RuleKind::SrcGeoIp("cn".into()));
        assert_eq!(config.rules[1], config.rules[2]);
        assert!(matches!(
            config.rules[3].kind,
            RuleKind::SrcIpCidr(IpCidr {
                network: IpAddr::V6(_),
                ..
            })
        ));
        assert!(matches!(
            config.rules[4].kind,
            RuleKind::SrcIpCidr(IpCidr {
                network: IpAddr::V4(_),
                ..
            })
        ));
        assert_eq!(
            config.rules[7].kind,
            RuleKind::InPorts(vec![
                PortRange { start: 0, end: 0 },
                PortRange {
                    start: 1080,
                    end: 1081
                },
                PortRange {
                    start: 65535,
                    end: 65535
                }
            ])
        );
        crate::routing::RuleSet::compile(config.take_runtime_rules()).unwrap();
        // Authentication hashing has no meaning for round robin.
        assert!(Config::parse_yaml(b"mixed-port: 1080\nproxy-groups: [{name: pool, type: load-balance, strategy: round-robin, hash-key: in-user, proxies: [DIRECT]}]").is_err());
    }

    #[test]
    fn yaml_templates_feed_logical_domain_and_source_rules() {
        use crate::routing::{RoutingContext, RuleEvaluation, RuleSet};
        let yaml = r#"
mixed-port: 0
allow-lan: true
authentication: [user:password]
tun: {enable: true}
proxies:
  - &base {name: "first/#%", type: socks5, server: 192.0.2.1, port: 1080}
  - {<<: *base, name: second, port: 1081}
rules:
  - AND,((DOMAIN-WILDCARD,*.example.com),(SRC-IP-CIDR,10.0.0.0/8),(SRC-PORT,1000-2000),(NOT,((NETWORK,UDP)))),REJECT
  - 'DOMAIN-REGEX,^a{1,2}\.example\.com$,second'
"#;
        let mut config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config.proxies[1].server_endpoint(),
            Some(("192.0.2.1", 1081))
        );
        let rules = RuleSet::compile(config.take_runtime_rules()).unwrap();
        let destination = crate::session::Destination::domain("AA.example.com", 443).unwrap();
        let mut context = RoutingContext::new(Network::Tcp, &destination).unwrap();
        context.set_source("10.1.2.3:1500".parse().unwrap());
        let RuleEvaluation::Matched(result) = rules.evaluate(&context) else {
            panic!("rule match")
        };
        assert_eq!(result.action, RuleAction::Reject);
        context.set_source("192.0.2.2:1500".parse().unwrap());
        let RuleEvaluation::Matched(result) = rules.evaluate(&context) else {
            panic!("regex match")
        };
        assert_eq!(
            result.action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::from_index(1)))
        );
        assert!(
            Config::parse_yaml(b"mixed-port: 1080\nproxies: &recursive [*recursive]\n").is_err()
        );
    }

    const CURRENT_TLS: &str = r#"mixed-port: 1080
authentication:
  - measure:secret
tun:
  enable: true
  mtu: 1500
rules:
  - MATCH,proxy
proxies:
  - name: proxy
    type: vless
    server: 203.0.113.1
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    flow: ""
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      path: /x
      host: example.com
      mode: auto
"#;

    const CURRENT_PROXY: &str = r#"
proxies:
  - name: proxy
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    flow: ""
    servername: edge.example.com
    alpn: [h2]
    xhttp-opts:
      host: edge.example.com
      path: /onev
      mode: auto
"#;

    const SOCKS_PROXY_ENTRY: &str = r#"  - name: socks-hop
    type: socks5
    server: socks.example.com
    port: 1080
    udp: true
    username: user
    password: password
"#;

    const CURRENT_ANYTLS: &str = r#"mixed-port: 1080
authentication:
  - measure:secret
rules:
  - MATCH,anytls-node
proxies:
  - name: anytls-node
    type: anytls
    server: anytls.example.com
    port: 443
    password: private-anytls-password
"#;

    fn current_yaml(fields: &str) -> String {
        let default_rules = if fields
            .lines()
            .any(|line| line.trim_ascii_start().starts_with("rules:"))
        {
            ""
        } else {
            "rules:\n  - MATCH,proxy\n"
        };
        format!("{fields}\n{default_rules}{CURRENT_PROXY}")
    }

    fn with_sniffer(sniffer: &str) -> String {
        CURRENT_TLS.replacen("proxies:\n", &format!("sniffer:\n{sniffer}\nproxies:\n"), 1)
    }

    fn with_geodata(fields: &str) -> String {
        current_yaml(&format!(
            "geodata-mode: true\n{fields}\nmixed-port: 1080\nauthentication:\n  - measure:secret"
        ))
    }

    fn two_proxy_yaml(fields: &str) -> String {
        format!("{}{SOCKS_PROXY_ENTRY}", current_yaml(fields))
    }

    fn with_proxy_groups(groups: &str, fields: &str) -> String {
        current_yaml(fields).replacen(
            "\nproxies:",
            &format!("\nproxy-groups:\n{groups}\nproxies:"),
            1,
        )
    }

    fn second_vless_entry() -> String {
        CURRENT_PROXY
            .strip_prefix("\nproxies:\n")
            .expect("CURRENT_PROXY starts with its collection key")
            .replace("name: proxy", "name: vless-two")
            .replace("edge.example.com", "second.example.com")
            .replace(
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
            )
    }

    fn socks_proxy_entries(count: usize, chained: bool) -> String {
        assert!(count > 0);
        let mut entries = String::new();
        for index in 0..count {
            entries.push_str(&format!("  - name: node-{index}\n    type: socks5\n"));
            if chained && index > 0 {
                entries.push_str(&format!("    dialer-proxy: node-{}\n", index - 1));
            }
            entries.push_str(&format!(
                "    server: node-{index}.example.com\n    port: 1080\n    udp: true\n"
            ));
        }
        entries
    }

    fn first_vless(config: &Config) -> &VlessOutboundConfig {
        let ProxyProtocol::Vless(vless) = &config.proxies[0].protocol else {
            panic!("expected VLESS proxy");
        };
        vless
    }

    fn first_xhttp_download(config: &Config) -> &XHttpDownloadConfig {
        first_vless(config)
            .download()
            .expect("expected XHTTP download settings")
    }

    fn reality_yaml() -> String {
        let key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        CURRENT_TLS.replace(
            "    servername: example.com\n",
            &format!(
                "    servername: example.com\n    reality-opts:\n      public-key: {key}\n      short-id: 01a2\n"
            ),
        )
    }

    fn with_xhttp_download(yaml: &str, fields: &str) -> String {
        let download = if fields.is_empty() {
            "      download-settings: {}\n".to_owned()
        } else {
            let fields = fields
                .lines()
                .map(|line| format!("        {line}\n"))
                .collect::<String>();
            format!("      download-settings:\n{fields}")
        };
        yaml.replacen(
            "      mode: auto\n",
            &format!("      mode: auto\n{download}"),
            1,
        )
    }

    #[test]
    fn parses_the_strict_tls_subset() {
        assert_eq!(ProxyId::new(0).unwrap().index(), 0);
        assert_eq!(ProxyId::new(1).unwrap().index(), 1);
        assert_eq!(
            ProxyId::new(usize::MAX).expect("ProxyId has no count-based ceiling"),
            ProxyId(usize::MAX)
        );
        let config = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.proxies[0].tag, "proxy");
        assert!(config.proxies[0].udp);
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap()))
        );
        assert_eq!(first_vless(&config).address, "203.0.113.1");
        assert!(matches!(
            &first_vless(&config).security,
            SecurityConfig::Tls(TlsConfig { server_name, .. }) if server_name == "example.com"
        ));
        assert_eq!(
            first_vless(&config).xhttp().unwrap().mode,
            XHttpMode::PacketUp
        );
        assert!(first_vless(&config).xhttp().unwrap().download.is_none());
    }

    #[test]
    fn parses_the_complete_geodata_update_contract() {
        let config = Config::parse_yaml(
            with_geodata(
                r#"geox-url:
  geoip: https://geo.example.test/custom-geoip.dat?channel=stable
  geosite: https://geo.example.test/custom-geosite.dat
geo-auto-update: true
geo-update-interval: 24"#,
            )
            .as_bytes(),
        )
        .unwrap();
        let update = config
            .geodata_update
            .expect("complete GeoData fields normalize into an update config");
        assert!(update.auto_update);
        assert_eq!(update.interval_hours, GEO_UPDATE_INTERVAL_HOURS);
        assert_eq!(
            update.urls.geoip,
            "https://geo.example.test/custom-geoip.dat?channel=stable"
        );
        assert_eq!(
            update.urls.geosite,
            "https://geo.example.test/custom-geosite.dat"
        );

        let disabled = Config::parse_yaml(
            with_geodata(
                r#"geox-url:
  geoip: https://geo.example.test/geoip.dat
  geosite: https://geo.example.test/geosite.dat
geo-auto-update: false
geo-update-interval: 24"#,
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(
            !disabled
                .geodata_update
                .expect("disabled updater remains explicit configuration")
                .auto_update
        );
        let defaults = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert!(!defaults.geodata_update.unwrap().auto_update);
        assert!(defaults.etag_support);
    }

    #[test]
    fn geodata_mode_defaults_to_mmdb_and_urls_remain_independent() {
        let default = Config::parse_yaml(b"rules: ['GEOIP,CN,DIRECT']").unwrap();
        let update = default.geodata_update.unwrap();
        assert!(!update.geodata_mode);
        assert_eq!(update.urls.mmdb, default_mmdb_url());
        let explicit = Config::parse_yaml(b"geodata-mode: true\ngeox-url: {mmdb: https://assets.example.test/country}\nrules: ['GEOIP,CN,DIRECT']").unwrap();
        let update = explicit.geodata_update.unwrap();
        assert!(update.geodata_mode);
        assert_eq!(update.urls.mmdb, "https://assets.example.test/country");
        assert_eq!(update.urls.geoip, default_geoip_url());
    }

    #[test]
    fn geodata_fields_have_independent_defaults_and_configurable_intervals() {
        let config = Config::parse_yaml(with_geodata("geo-auto-update: true\ngeo-update-interval: 6\netag-support: false\nglobal-ua: custom-agent\ngeox-url:\n  geosite: https://rules.example.test/site.dat").as_bytes()).unwrap();
        assert!(!config.etag_support);
        assert_eq!(config.global_ua, "custom-agent");
        let update = config.geodata_update.unwrap();
        assert!(update.auto_update);
        assert_eq!(update.interval_hours, 6);
        assert_eq!(update.urls.geoip, default_geoip_url());
        assert_eq!(update.urls.geosite, "https://rules.example.test/site.dat");
        assert_eq!(
            Config::parse_yaml(with_geodata("geo-update-interval: 0").as_bytes())
                .unwrap()
                .geodata_update
                .unwrap()
                .interval_hours,
            0
        );
    }

    #[test]
    fn validates_geodata_update_interval_and_url_shape() {
        let complete = |geoip: &str, geosite: &str, interval: &str| {
            with_geodata(&format!(
                "geox-url:\n  geoip: {geoip}\n  geosite: {geosite}\ngeo-auto-update: true\ngeo-update-interval: {interval}"
            ))
        };
        for yaml in [
            complete(
                "https://geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24.0",
            ),
            complete(
                "ftp://geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://127.0.0.1/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://[::1]/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://user%GG:password@geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://user%3Aname:password@geo.example.test/geoip.dat",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
            complete(
                "https://geo.example.test/geoip.dat#latest",
                "https://geo.example.test/geosite.dat",
                "24",
            ),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let prefix = "https://geo.example.test/";
        let maximum = format!("{prefix}{}", "g".repeat(MAX_GEOX_URL_BYTES - prefix.len()));
        assert_eq!(maximum.len(), MAX_GEOX_URL_BYTES);
        assert!(
            Config::parse_yaml(
                complete(&maximum, "https://geo.example.test/geosite.dat", "24").as_bytes()
            )
            .is_ok()
        );
        let oversized = format!("{maximum}x");
        let error = Config::parse_yaml(
            complete(&oversized, "https://geo.example.test/geosite.dat", "24").as_bytes(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("4096-byte limit"), "{error}");
    }

    #[test]
    fn geodata_update_requires_https() {
        for url in [
            "http://geo.example.test/geoip.dat",
            "http://geo.example.test:8080/geosite.dat",
        ] {
            assert!(normalize_geox_url(url.to_owned(), "geox-url.geoip").is_err());
        }
        for url in [
            "http://127.0.0.1/geoip.dat",
            "http://[::1]/geoip.dat",
            "http://user:password@geo.example.test/geoip.dat",
            "http://@geo.example.test/geoip.dat",
            "http://geo.example.test/geoip.dat#latest",
        ] {
            assert!(normalize_geox_url(url.to_owned(), "geox-url.geoip").is_err());
        }
    }

    #[test]
    fn geodata_url_basic_auth_keeps_validation_and_debug_private() {
        let yaml = with_geodata(
            "geox-url: {geoip: 'https://subscriber:password@geo.example.test/private-path?token=private-query'}",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let debug = format!("{:?}", config.geodata_update.as_ref().unwrap());
        for secret in ["subscriber", "password", "private-path", "private-query"] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("https://geo.example.test"));
        let raw: RawGeoDataUrls=serde_yaml_ng::from_str("geoip: 'https://subscriber:password@geo.example.test/private-path?token=private-query'").unwrap();
        let debug = format!("{raw:?}");
        assert!(!debug.contains("password"));
        assert!(!debug.contains("private-query"));
    }

    #[test]
    fn defaults_documented_fields() {
        let yaml = CURRENT_TLS
            .replace("    flow: \"\"\n", "")
            .replace("    encryption: none\n", "")
            .replace("    alpn: [h2]\n", "")
            .replace(
                "    xhttp-opts:\n      path: /x\n      host: example.com\n      mode: auto\n",
                "",
            );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(first_vless(&config).flow, "");
        assert_eq!(first_vless(&config).xhttp().unwrap().path, "/");
        assert_eq!(first_vless(&config).xhttp().unwrap().host, "example.com");
        assert_eq!(
            first_vless(&config).xhttp().unwrap().mode,
            XHttpMode::PacketUp
        );
        assert!(matches!(
            config.inbounds[1],
            InboundConfig::Tun(TunInboundConfig { mtu: 1_500, .. })
        ));
        assert_eq!(config.sniffer, SnifferConfig::disabled());
    }

    #[test]
    fn parses_and_normalizes_the_strict_mihomo_style_sniffer_subset() {
        let config = Config::parse_yaml(
            with_sniffer(
                r#"  enable: true
  sniff:
    HTTP:
    TLS:
      ports: [443, "8443", "8444-8446", "8445-8447"]
    QUIC:"#,
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(config.sniffer.enable);
        assert_eq!(
            config.sniffer.http_ports.as_ref(),
            &[PortRange {
                start: 0,
                end: u16::MAX
            }]
        );
        assert_eq!(
            config.sniffer.tls_ports.as_ref(),
            &[
                PortRange {
                    start: 443,
                    end: 443
                },
                PortRange {
                    start: 8_443,
                    end: 8_447
                }
            ]
        );
        assert!(config.sniffer.matches_http_port(80));
        assert!(config.sniffer.matches_http_port(8080));
        assert!(config.sniffer.matches_tls_port(8445));
        assert!(!config.sniffer.matches_tls_port(8448));
        assert_eq!(
            config.sniffer.quic_ports.as_ref(),
            &[PortRange {
                start: 0,
                end: u16::MAX
            }]
        );
        assert!(config.sniffer.matches_quic_port(443));
        assert!(config.sniffer.matches_quic_port(8443));

        let http_only =
            Config::parse_yaml(with_sniffer("  enable: true\n  sniff:\n    HTTP: {}").as_bytes())
                .unwrap();
        assert!(http_only.sniffer.enable);
        assert!(http_only.sniffer.matches_http_port(80));
        assert!(http_only.sniffer.tls_ports.is_empty());
        assert!(http_only.sniffer.quic_ports.is_empty());

        let quic_only =
            Config::parse_yaml(with_sniffer("  enable: true\n  sniff:\n    QUIC: {}").as_bytes())
                .unwrap();
        assert!(quic_only.sniffer.matches_quic_port(443));
        assert!(quic_only.sniffer.http_ports.is_empty());
        assert!(quic_only.sniffer.tls_ports.is_empty());

        let shared_port = Config::parse_yaml(
            with_sniffer(
                "  enable: true\n  sniff:\n    HTTP:\n      ports: [443]\n    TLS:\n      ports: [8443]\n    QUIC:\n      ports: [443, 8443]",
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(shared_port.sniffer.matches_http_port(443));
        assert!(shared_port.sniffer.matches_tls_port(8443));
        assert!(shared_port.sniffer.matches_quic_port(443));
        assert!(shared_port.sniffer.matches_quic_port(8443));
    }

    #[test]
    fn disabled_sniffer_may_omit_or_preconfigure_protocols() {
        let omitted = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert_eq!(omitted.sniffer, SnifferConfig::disabled());

        let configured = Config::parse_yaml(
            with_sniffer(
                r#"  enable: false
  sniff:
    HTTP:
      ports: ["8080-8081"]
    QUIC:
      ports: ["8443-8444"]"#,
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(!configured.sniffer.enable);
        assert_eq!(
            configured.sniffer.http_ports.as_ref(),
            &[PortRange {
                start: 8080,
                end: 8081
            }]
        );
        assert!(configured.sniffer.tls_ports.is_empty());
        assert_eq!(
            configured.sniffer.quic_ports.as_ref(),
            &[PortRange {
                start: 8443,
                end: 8444
            }]
        );
    }

    #[test]
    fn rejects_invalid_sniffer_shapes_and_ports() {
        let too_many_ports = (1..=MAX_SNIFFER_PORT_ITEMS + 1)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        for yaml in [
            with_sniffer("  enable: \"true\"\n  sniff:\n    HTTP: {}"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [65536]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"+80\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\" 80\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"80 \"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"８０\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"443-\"]"),
            with_sniffer("  enable: true\n  sniff:\n    HTTP:\n      ports: [\"444-443\"]"),
            with_sniffer("  enable: true\n  sniff:\n    QUIC:\n      ports: [\"444-443\"]"),
            with_sniffer(&format!(
                "  enable: true\n  sniff:\n    HTTP:\n      ports: [{too_many_ports}]"
            )),
            with_sniffer(&format!(
                "  enable: true\n  sniff:\n    QUIC:\n      ports: [{too_many_ports}]"
            )),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn brackets_an_ipv6_server_name_used_as_the_default_xhttp_host() {
        let yaml = CURRENT_TLS
            .replace("servername: example.com", "servername: '::1'")
            .replace("      host: example.com\n", "");
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(first_vless(&config).xhttp().unwrap().host, "[::1]");
    }

    #[test]
    fn parses_and_decodes_reality() {
        let config = Config::parse_yaml(reality_yaml().as_bytes()).unwrap();
        let SecurityConfig::Reality(reality) = &first_vless(&config).security else {
            panic!("expected REALITY");
        };
        assert_eq!(reality.server_name, "example.com");
        assert_eq!(reality.public_key, [7_u8; 32]);
        assert_eq!(reality.short_id, [1, 0xa2]);
        assert_eq!(
            first_vless(&config).xhttp().unwrap().mode,
            XHttpMode::StreamOne
        );
    }

    #[test]
    fn auto_mode_tracks_the_security_transport() {
        let tls = Config::parse_yaml(CURRENT_TLS.as_bytes()).unwrap();
        assert_eq!(first_vless(&tls).xhttp().unwrap().mode, XHttpMode::PacketUp);
        let reality = Config::parse_yaml(reality_yaml().as_bytes()).unwrap();
        assert_eq!(
            first_vless(&reality).xhttp().unwrap().mode,
            XHttpMode::StreamOne
        );
        let reality_with_download = with_xhttp_download(&reality_yaml(), "");
        let reality_with_download = Config::parse_yaml(reality_with_download.as_bytes()).unwrap();
        assert_eq!(
            first_vless(&reality_with_download).xhttp().unwrap().mode,
            XHttpMode::StreamUp
        );
    }

    #[test]
    fn accepts_explicit_supported_xhttp_modes() {
        let packet_up = CURRENT_TLS.replace("mode: auto", "mode: packet-up");
        let packet_up = Config::parse_yaml(packet_up.as_bytes()).unwrap();
        assert_eq!(
            first_vless(&packet_up).xhttp().unwrap().mode,
            XHttpMode::PacketUp
        );
        let stream_one = CURRENT_TLS.replace("mode: auto", "mode: stream-one");
        let stream_one = Config::parse_yaml(stream_one.as_bytes()).unwrap();
        assert_eq!(
            first_vless(&stream_one).xhttp().unwrap().mode,
            XHttpMode::StreamOne
        );
        let stream_up = CURRENT_TLS.replace("mode: auto", "mode: stream-up");
        let stream_up = Config::parse_yaml(stream_up.as_bytes()).unwrap();
        assert_eq!(
            first_vless(&stream_up).xhttp().unwrap().mode,
            XHttpMode::StreamUp
        );

        for (mode, expected) in [
            ("packet-up", XHttpMode::PacketUp),
            ("stream-up", XHttpMode::StreamUp),
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, "")
                .replace("mode: auto", &format!("mode: {mode}"));
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert_eq!(first_vless(&config).xhttp().unwrap().mode, expected);
        }
    }

    #[test]
    fn normalizes_xhttp_download_security_inheritance_and_reality_override() {
        let tls_inherited = with_xhttp_download(CURRENT_TLS, "");
        let tls_inherited = Config::parse_yaml(tls_inherited.as_bytes()).unwrap();
        let download = first_xhttp_download(&tls_inherited);
        assert_eq!(download.address, "203.0.113.1");
        assert_eq!(download.port, 443);
        assert_eq!(download.path, "/x");
        assert_eq!(download.host, "example.com");
        assert!(matches!(
            &download.security,
            SecurityConfig::Tls(TlsConfig { server_name, .. }) if server_name == "example.com"
        ));
        assert_eq!(
            first_vless(&tls_inherited).xhttp().unwrap().mode,
            XHttpMode::PacketUp
        );

        let download_reality_key = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let tls_to_reality = with_xhttp_download(
            CURRENT_TLS,
            &format!(
                "server: download.example.com\nport: 8443\ntls: true\nservername: reality-download.example.com\nalpn: [h2]\npath: /down\nhost: cdn.example.com\nreality-opts:\n  public-key: {download_reality_key}\n  short-id: 02a3"
            ),
        );
        let tls_to_reality_without_explicit_tls = tls_to_reality.replace("        tls: true\n", "");
        let inherited_tls =
            Config::parse_yaml(tls_to_reality_without_explicit_tls.as_bytes()).unwrap();
        assert!(matches!(
            &first_xhttp_download(&inherited_tls).security,
            SecurityConfig::Reality(_)
        ));
        let tls_to_reality = Config::parse_yaml(tls_to_reality.as_bytes()).unwrap();
        let download = first_xhttp_download(&tls_to_reality);
        assert_eq!(download.address, "download.example.com");
        assert_eq!(download.port, 8_443);
        assert_eq!(download.path, "/down");
        assert_eq!(download.host, "cdn.example.com");
        let SecurityConfig::Reality(download_reality) = &download.security else {
            panic!("expected download REALITY");
        };
        assert_eq!(download_reality.server_name, "reality-download.example.com");
        assert_eq!(download_reality.public_key, [9_u8; 32]);
        assert_eq!(download_reality.short_id, [2, 0xa3]);
        assert_eq!(
            first_vless(&tls_to_reality).xhttp().unwrap().mode,
            XHttpMode::PacketUp
        );

        let reality_inherited = with_xhttp_download(&reality_yaml(), "");
        let reality_inherited = Config::parse_yaml(reality_inherited.as_bytes()).unwrap();
        assert_eq!(
            &first_xhttp_download(&reality_inherited).security,
            &first_vless(&reality_inherited).security
        );
        assert_eq!(
            first_vless(&reality_inherited).xhttp().unwrap().mode,
            XHttpMode::StreamUp
        );

        let reality_with_explicit_tls = with_xhttp_download(
            &reality_yaml(),
            "tls: true\nservername: tls-download.example.com",
        );
        let reality_with_explicit_tls =
            Config::parse_yaml(reality_with_explicit_tls.as_bytes()).unwrap();
        let SecurityConfig::Reality(download_reality) =
            &first_xhttp_download(&reality_with_explicit_tls).security
        else {
            panic!("explicit download tls must not clear inherited REALITY");
        };
        assert_eq!(download_reality.server_name, "tls-download.example.com");
        assert_eq!(
            first_vless(&reality_with_explicit_tls)
                .xhttp()
                .unwrap()
                .mode,
            XHttpMode::StreamUp
        );
    }

    #[test]
    fn xhttp_download_defaults_follow_raw_mihomo_fallback_order() {
        let implicit_outer = CURRENT_TLS
            .replace("    servername: example.com\n", "")
            .replace("      host: example.com\n", "");
        let implicit_outer =
            with_xhttp_download(&implicit_outer, "server: download.example.com\nport: 8443");
        let implicit_outer = Config::parse_yaml(implicit_outer.as_bytes()).unwrap();
        let download = first_xhttp_download(&implicit_outer);
        assert_eq!(download.address, "download.example.com");
        assert_eq!(download.port, 8_443);
        assert_eq!(download.security.server_name(), "download.example.com");
        assert_eq!(download.host, "download.example.com");

        let inherited_sni = CURRENT_TLS.replace("      host: example.com\n", "");
        let inherited_sni =
            with_xhttp_download(&inherited_sni, "server: download.example.com\nport: 8443");
        let inherited_sni = Config::parse_yaml(inherited_sni.as_bytes()).unwrap();
        let download = first_xhttp_download(&inherited_sni);
        assert_eq!(download.security.server_name(), "example.com");
        assert_eq!(download.host, "example.com");

        let inherited_host = CURRENT_TLS.replace("    servername: example.com\n", "");
        let inherited_host =
            with_xhttp_download(&inherited_host, "server: download.example.com\nport: 8443");
        let inherited_host = Config::parse_yaml(inherited_host.as_bytes()).unwrap();
        let download = first_xhttp_download(&inherited_host);
        assert_eq!(download.security.server_name(), "download.example.com");
        assert_eq!(download.host, "example.com");

        let ipv6_download = CURRENT_TLS
            .replace("    servername: example.com\n", "")
            .replace("      host: example.com\n", "");
        let ipv6_download =
            with_xhttp_download(&ipv6_download, "server: '2001:db8::10'\nport: 8443");
        let ipv6_download = Config::parse_yaml(ipv6_download.as_bytes()).unwrap();
        let download = first_xhttp_download(&ipv6_download);
        assert_eq!(download.security.server_name(), "2001:db8::10");
        assert_eq!(download.host, "[2001:db8::10]");
    }

    #[test]
    fn rejects_stream_one_with_xhttp_download_settings() {
        let yaml = with_xhttp_download(CURRENT_TLS, "").replace("mode: auto", "mode: stream-one");
        let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("stream-one")
                && error.to_string().contains("download-settings"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_or_null_xhttp_download_fields() {
        let download_null = CURRENT_TLS.replace(
            "      mode: auto\n",
            "      mode: auto\n      download-settings: null\n",
        );
        assert!(Config::parse_yaml(download_null.as_bytes()).is_err());

        for field in [
            "server",
            "port",
            "tls",
            "servername",
            "alpn",
            "reality-opts",
            "path",
            "host",
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, &format!("{field}: null"));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{field}");
        }

        for fields in [
            "tls: 'false'",
            "alpn: [unknown]",
            "alpn: [h3, h2]",
            "server: 'bad host'",
            "port: 0",
            "servername: 'bad host'",
            "path: 'bad-path'",
            "host: '[broken'",
        ] {
            let yaml = with_xhttp_download(CURRENT_TLS, fields);
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{fields}");
        }
    }

    #[test]
    fn rejects_unsupported_xhttp_download_fields_fail_closed() {
        for fields in ["restls-opts: {}", "mode: stream-up", "typo: true"] {
            let yaml = with_xhttp_download(CURRENT_TLS, fields);
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "{fields}: {error}"
            );
        }

        for unsupported in ["    restls-opts: {}\n"] {
            let yaml = CURRENT_TLS.replace(
                "    xhttp-opts:\n",
                &format!("{unsupported}    xhttp-opts:\n"),
            );
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "{unsupported}: {error}"
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_at_every_depth() {
        for yaml in [
            CURRENT_TLS.replacen("mixed-port: 1080\n", "log: {}\nmixed-port: 1080\n", 1),
            CURRENT_TLS.replacen(
                "mixed-port: 1080\n",
                "ipv6-mode: true\nmixed-port: 1080\n",
                1,
            ),
            CURRENT_TLS.replace("tun:\n", "tun:\n  typo: true\n"),
            with_sniffer("  enable: true\n  typo: true\n  sniff:\n    HTTP: {}"),
            CURRENT_TLS.replace("  - name: proxy\n", "  - typo: true\n    name: proxy\n"),
            CURRENT_TLS.replace("    server: ", "    vnext: []\n    server: "),
            CURRENT_TLS.replace("    network: xhttp", "    typo: true\n    network: xhttp"),
            CURRENT_TLS.replace("      path: /x", "      typo: true\n      path: /x"),
            reality_yaml().replace(
                "      public-key:",
                "      unknown-reality-option: true\n      public-key:",
            ),
        ] {
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }

    #[test]
    fn rejects_removed_xray_style_vless_shapes() {
        for yaml in [
            CURRENT_TLS.replace("    server: ", "    settings: {}\n    server: "),
            CURRENT_TLS.replace("    server: ", "    streamSettings: {}\n    server: "),
            CURRENT_TLS.replace("    type: vless", "    protocol: vless"),
            CURRENT_TLS.replace("  - name: proxy", "  - tag: proxy"),
            CURRENT_TLS.replace("    server: ", "    address: "),
            CURRENT_TLS.replace("    uuid: ", "    id: "),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_removed_default_proxy_and_inbound_outbound_fields() {
        let yaml = CURRENT_TLS.replacen(
            "mixed-port: 1080\n",
            "default-proxy: proxy\nmixed-port: 1080\n",
            1,
        );
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let old = r#"inbounds: []
outbounds: []
"#;
        assert!(Config::parse_yaml(old.as_bytes()).is_err());
    }

    #[test]
    fn validates_listener_and_tun_constraints() {
        assert!(
            Config::parse_yaml(CURRENT_TLS.replace("mtu: 1500", "mtu: 1279").as_bytes()).is_err()
        );
        let disabled = CURRENT_TLS
            .replace("enable: true", "enable: false")
            .replace(
                "mixed-port: 1080\nauthentication:\n  - measure:secret\n",
                "",
            );
        let config = Config::parse_yaml(disabled.as_bytes()).unwrap();
        assert!(config.inbounds.is_empty());
        assert!(!config.tun.enable);
    }

    #[test]
    fn parses_the_strict_mihomo_style_traffic_controller_subset() {
        let authenticated = Config::parse_yaml(
            current_yaml(
                r#"external-controller: "127.0.0.1:19090"
secret: "random token"
tun:
  enable: true"#,
            )
            .as_bytes(),
        )
        .unwrap();
        let controller = authenticated
            .external_controller
            .expect("configured controller");
        assert_eq!(controller.listen, "127.0.0.1:19090".parse().unwrap());
        assert_eq!(controller.secret.as_deref(), Some("random token"));

        let unauthenticated = Config::parse_yaml(
            current_yaml(
                r#"external-controller: "[::1]:19091"
tun:
  enable: true"#,
            )
            .as_bytes(),
        )
        .unwrap();
        let controller = unauthenticated
            .external_controller
            .expect("configured controller");
        assert_eq!(controller.listen, "[::1]:19091".parse().unwrap());
        assert!(controller.secret.is_none());

        for (address, expected) in [
            ("0.0.0.0:9090", "0.0.0.0:9090"),
            ("[::]:9090", "[::]:9090"),
            ("192.0.2.1:9090", "192.0.2.1:9090"),
            ("127.0.0.1:0", "127.0.0.1:0"),
            ("localhost:0", "127.0.0.1:0"),
            (":0", "[::]:0"),
        ] {
            let fields = format!("external-controller: '{address}'\nsecret: ''");
            let config = Config::parse_yaml(current_yaml(&fields).as_bytes()).unwrap();
            let controller = config.external_controller.unwrap();
            assert_eq!(controller.listen, expected.parse().unwrap());
            assert!(controller.secret.is_none());
        }
        let secret = "s".repeat(crate::inbound::DEFAULT_HEADER_LIMIT + 1);
        let fields = format!("external-controller: '127.0.0.1:0'\nsecret: '{secret}'");
        let config = Config::parse_yaml(current_yaml(&fields).as_bytes()).unwrap();
        assert_eq!(
            config.external_controller.unwrap().secret.as_deref(),
            Some(secret.as_str())
        );

        let debug = format!(
            "{:?}",
            ExternalControllerConfig {
                listen: "127.0.0.1:19090".parse().unwrap(),
                secret: Some("private-token".to_owned()),
                ..ExternalControllerConfig::default()
            }
        );
        assert!(debug.contains("authenticated: true"));
        assert!(!debug.contains("private-token"));
    }

    #[test]
    fn admits_mixed_only_direct_controller() {
        let config = Config::parse_yaml(
            b"mixed-port: 1080\nexternal-controller: 127.0.0.1:19090\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        assert!(config.external_controller.is_some());
        assert!(config.proxies.is_empty());
        for controller in ["", "external-controller: \"\"\n"] {
            let yaml = format!("{controller}secret: token\nrules: ['MATCH,DIRECT']\n");
            let disabled = Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert!(disabled.external_controller.is_none());
        }
    }

    #[test]
    fn rejects_malformed_traffic_controller_addresses() {
        for address in [
            "127.0.0.1",
            "127.0.0.1:65536",
            "localhost:not-a-port",
            "controller.example:9090",
            "::1:9090",
        ] {
            let fields = format!("external-controller: '{address}'");
            let error = Config::parse_yaml(current_yaml(&fields).as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("external-controller"),
                "unexpected error for {address:?}: {error}"
            );
        }

        assert!(
            Config::parse_yaml(
                current_yaml("external-controller: null\ntun:\n  enable: true").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn validates_strict_mixed_port_authentication_contract() {
        let yaml = current_yaml(
            r#"mixed-port: 1080
authentication:
  - "用户:密:码""#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let [InboundConfig::Mixed(mixed)] = config.inbounds.as_slice() else {
            panic!("mixed-only config must normalize exactly one mixed inbound");
        };
        assert!(
            mixed
                .auth
                .as_ref()
                .unwrap()
                .matches("用户".as_bytes(), "密:码".as_bytes())
        );

        for (user, password) in [
            ("", ""),
            ("", "secret"),
            ("user", ""),
            (&"u".repeat(600), &"p".repeat(600)),
        ] {
            let config = Config::parse_yaml(
                current_yaml(&format!(
                    "mixed-port: 1080\nauthentication: ['{user}:{password}']"
                ))
                .as_bytes(),
            )
            .unwrap();
            let [InboundConfig::Mixed(mixed)] = config.inbounds.as_slice() else {
                panic!("missing mixed inbound");
            };
            assert!(
                mixed
                    .auth
                    .as_ref()
                    .unwrap()
                    .matches(user.as_bytes(), password.as_bytes())
            );
        }
        let error = Config::parse_yaml(
            current_yaml("mixed-port: 1080\nauthentication: [missing-separator]").as_bytes(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authentication entry must use user:password")
        );
        assert!(
            Config::parse_yaml(
                current_yaml("mixed-port: 1080\nauthentication: measure:secret").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn mixed_localhost_and_null_inputs_keep_reference_defaults() {
        for authentication in ["null", "[]"] {
            let config = Config::parse_yaml(current_yaml(&format!(
                "mixed-port: 1080\nallow-lan: true\nbind-address: localhost\nauthentication: {authentication}"
            )).as_bytes()).unwrap();
            let [InboundConfig::Mixed(mixed)] = config.inbounds.as_slice() else {
                panic!("missing mixed inbound");
            };
            assert!(!mixed.access.allow_lan);
            assert!(mixed.access.bind_address.is_none());
            assert!(mixed.auth.is_none());
        }
        let yaml = with_proxy_groups(
            "  - name: choice\n    type: select\n    proxies: [DIRECT, proxy]\n    default-selected: null",
            "rules: ['MATCH,choice']",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(config.proxy_groups[0].initial_member, 0);
    }

    #[test]
    fn mixed_port_supports_local_and_tun_runtime_shapes() {
        for fields in [
            "mixed-port: 1080",
            "mixed-port: 65535\nauthentication: []",
            "mixed-port: 1080\nallow-lan: true\nauthentication: ['用户:密:码']",
            "mixed-port: 1080\ntun: {enable: true}",
        ] {
            let config = Config::parse_yaml(current_yaml(fields).as_bytes()).unwrap();
            assert!(config.mixed_port.is_some());
            let mixed = config
                .inbounds
                .iter()
                .find_map(|inbound| match inbound {
                    InboundConfig::Mixed(config) => Some(config),
                    InboundConfig::Tun(_) => None,
                })
                .unwrap();
            assert_eq!(mixed.tag, "mixed-in");
            assert_eq!(Some(mixed.port), config.mixed_port);
            assert_eq!(config.inbounds.len(), if config.tun.enable { 2 } else { 1 });
        }
    }

    #[test]
    fn mixed_port_rejects_retired_ports_and_independent_listener_settings() {
        for (field, value) in [
            ("port", "1080"),
            ("socks-port", "1080"),
            ("mix-port", "1080"),
            ("listeners", "[]"),
            ("udp", "true"),
            ("udp", "false"),
            ("mixed-udp", "false"),
        ] {
            let fields = format!("mixed-port: 1080\n{field}: {value}");
            let error = Config::parse_yaml(current_yaml(&fields).as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn mixed_port_lan_access_does_not_require_credentials() {
        for authentication in ["", "\nauthentication: []"] {
            let fields = format!("mixed-port: 1080\nallow-lan: true{authentication}");
            let config = Config::parse_yaml(current_yaml(&fields).as_bytes()).unwrap();
            let [InboundConfig::Mixed(mixed)] = config.inbounds.as_slice() else {
                panic!("mixed listener");
            };
            assert!(mixed.access.allow_lan);
            assert!(mixed.auth.is_none());
        }
    }

    #[test]
    fn mixed_listener_defaults_disabled_port_and_optional_lan_authentication() {
        for fields in [
            "mixed-port: 1",
            "mixed-port: 65535",
            "mixed-port: 1080\nauthentication: []",
        ] {
            let config = Config::parse_yaml(current_yaml(fields).as_bytes()).unwrap();
            let [InboundConfig::Mixed(mixed)] = config.inbounds.as_slice() else {
                panic!("mixed listener")
            };
            assert!(mixed.auth.is_none());
            assert!(!mixed.access.allow_lan);
            assert!(mixed.access.ipv6);
        }
        for fields in [
            "",
            "mixed-port: 0",
            "tun: {enable: false}",
            "tun: {enable: true}",
            "mixed-port: 0\ntun: {enable: true}",
        ] {
            let config = Config::parse_yaml(current_yaml(fields).as_bytes()).unwrap();
            assert_eq!(config.mixed_port, None);
            assert!(
                !config
                    .inbounds
                    .iter()
                    .any(|inbound| matches!(inbound, InboundConfig::Mixed(_)))
            );
        }
        let yaml = current_yaml(
            "mixed-port: 1080\nipv6: false\nallow-lan: true\nauthentication: ['用户:密:码']",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let [InboundConfig::Mixed(mixed)] = config.inbounds.as_slice() else {
            panic!("mixed listener")
        };
        assert_eq!(
            mixed.access,
            ProxyAccess {
                bind_address: None,
                allow_lan: true,
                ipv6: false
            }
        );
        assert!(
            mixed
                .auth
                .as_ref()
                .unwrap()
                .matches("用户".as_bytes(), "密:码".as_bytes())
        );
        for fields in [
            "mixed-port: -1",
            "mixed-port: 65536",
            "mixed-port: 1.0",
            "mixed-port: null",
            "mixed-port: 1080\nallow-lan: null",
        ] {
            assert!(
                Config::parse_yaml(current_yaml(fields).as_bytes()).is_err(),
                "{fields}"
            );
        }
        for length in [85, 86] {
            let yaml = current_yaml(&format!(
                "mixed-port: 1080\nauthentication: ['{}:{}']",
                "用".repeat(length),
                "密".repeat(length)
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_ok());
        }
    }

    #[test]
    fn mixed_inbound_debug_redacts_credentials() {
        let inbound = MixedInboundConfig {
            access_rules: Default::default(),
            tag: "mixed-in".to_owned(),
            port: 1080,
            access: ProxyAccess {
                bind_address: None,
                allow_lan: false,
                ipv6: true,
            },
            auth: Some(ProxyCredentials::new("private-user", "private-password").unwrap()),
        };
        let debug = format!("{inbound:?}");
        assert!(debug.contains("MixedInboundConfig"));
        assert!(debug.contains("mixed-in"));
        assert!(debug.contains("1080"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
        // Deserializer diagnostics must not echo even malformed credential values.
        for authentication in [
            "private-auth-fixture",
            "[{private-auth-fixture: secret}]",
            "[123]",
        ] {
            let error = Config::parse_yaml(
                current_yaml(&format!(
                    "mixed-port: 1080\nauthentication: {authentication}"
                ))
                .as_bytes(),
            )
            .unwrap_err();
            assert!(!error.to_string().contains("private-auth-fixture"));
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn parses_the_strict_anytls_subset() {
        let config = Config::parse_yaml(CURRENT_ANYTLS.as_bytes()).unwrap();
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap()))
        );
        let proxy = &config.proxies[0];
        assert_eq!(proxy.tag, "anytls-node");
        assert!(!proxy.udp);
        assert_eq!(proxy.server_endpoint(), Some(("anytls.example.com", 443)));
        let ProxyProtocol::AnyTls(anytls) = &proxy.protocol else {
            panic!("expected AnyTLS proxy");
        };
        assert_eq!(anytls.password, "private-anytls-password");
        assert_eq!(anytls.server_name, "anytls.example.com");
        let debug = format!("{anytls:?}");
        assert!(debug.contains("AnyTlsOutboundConfig"));
        assert!(debug.contains("anytls.example.com"));
        assert!(!debug.contains("private-anytls-password"));

        let explicit = CURRENT_ANYTLS.replace(
            "    password: private-anytls-password",
            "    password: private-anytls-password\n    udp: true\n    sni: front.example.com",
        );
        let config = Config::parse_yaml(explicit.as_bytes()).unwrap();
        assert!(config.proxies[0].udp);
        let ProxyProtocol::AnyTls(anytls) = &config.proxies[0].protocol else {
            panic!("expected AnyTLS proxy");
        };
        assert_eq!(anytls.server_name, "front.example.com");
    }

    #[test]
    fn supports_anytls_as_a_chain_head() {
        let yaml = CURRENT_ANYTLS
            .replacen("proxies:\n", &format!("proxies:\n{SOCKS_PROXY_ENTRY}"), 1)
            .replace(
                "    password: private-anytls-password",
                "    password: private-anytls-password\n    dialer-proxy: socks-hop",
            );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(1).unwrap()))
        );
        assert_eq!(
            config.proxies[1].dialer_proxy,
            ProxyId::new(0).map(RouteTargetId::Proxy),
            "AnyTLS must participate in the same protocol-agnostic proxy graph"
        );
        assert!(matches!(
            config.proxies[1].protocol,
            ProxyProtocol::AnyTls(_)
        ));
    }

    #[test]
    fn validates_anytls_required_fields() {
        for yaml in [
            CURRENT_ANYTLS.replace("server: anytls.example.com", "server: 'bad host'"),
            CURRENT_ANYTLS.replace("port: 443", "port: 0"),
            CURRENT_ANYTLS.replace("    password: private-anytls-password\n", ""),
            CURRENT_ANYTLS.replace("password: private-anytls-password", "password: \"\""),
            CURRENT_ANYTLS.replace(
                "password: private-anytls-password",
                "password: private-anytls-password\n    sni: 'bad host'",
            ),
            CURRENT_ANYTLS.replace(
                "password: private-anytls-password",
                "password: private-anytls-password\n    sni: null",
            ),
            CURRENT_ANYTLS.replace(
                "password: private-anytls-password",
                &format!("password: {}", "p".repeat(MAX_ANYTLS_PASSWORD_BYTES + 1)),
            ),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn rejects_anytls_fields_outside_the_locked_subset() {
        let yaml = CURRENT_ANYTLS.replace(
            "    password: private-anytls-password",
            "    password: private-anytls-password\n    tls: true",
        );
        let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn anytls_alpn_and_certificate_policy_are_strict_and_preserve_order() {
        let configured = |fields: &str| {
            CURRENT_ANYTLS.replace(
                "    password: private-anytls-password",
                &format!("    password: private-anytls-password\n    {fields}"),
            )
        };
        for fields in ["alpn: []", "skip-cert-verify: false", "fingerprint: ''"] {
            let config = Config::parse_yaml(configured(fields).as_bytes()).unwrap();
            let ProxyProtocol::AnyTls(anytls) = &config.proxies[0].protocol else {
                panic!()
            };
            let tls = anytls.security.as_tls().unwrap();
            assert!(tls.alpn.is_empty());
            assert_eq!(tls.certificate, TlsCertificatePolicy::default());
            assert!(
                tls.identity.is_none() && tls.ech.is_none() && tls.client_fingerprint.is_none()
            );
        }
        let plain = "aB".repeat(32);
        let colon = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
        for pin in [plain, colon] {
            let config = Config::parse_yaml(
                configured(&format!(
                    "alpn: [h2, http/1.1, h2]\n    skip-cert-verify: true\n    fingerprint: '{pin}'"
                ))
                .as_bytes(),
            )
            .unwrap();
            let ProxyProtocol::AnyTls(anytls) = &config.proxies[0].protocol else {
                panic!()
            };
            assert_eq!(
                anytls.security.as_tls().unwrap().alpn,
                [b"h2".to_vec(), b"http/1.1".to_vec(), b"h2".to_vec()]
            );
            assert!(
                anytls
                    .security
                    .as_tls()
                    .unwrap()
                    .certificate
                    .skip_cert_verify
            );
            assert_eq!(
                anytls.security.as_tls().unwrap().certificate.fingerprint,
                Some([0xab; 32])
            );
        }
        for fields in [
            "alpn: null",
            "alpn: h2",
            "alpn: ['']",
            "skip-cert-verify: null",
            "skip-cert-verify: 'true'",
            "fingerprint: null",
            "fingerprint: chrome",
            "fingerprint: aa:bb",
        ] {
            assert!(
                Config::parse_yaml(configured(fields).as_bytes()).is_err(),
                "{fields}"
            );
        }
        assert!(
            Config::parse_yaml(configured(&format!("alpn: ['{}']", "x".repeat(255))).as_bytes())
                .is_ok()
        );
        assert!(
            Config::parse_yaml(configured(&format!("alpn: ['{}']", "x".repeat(256))).as_bytes())
                .is_err()
        );
        let oversized = std::iter::repeat_n(format!("'{}'", "x".repeat(255)), 256)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            Config::parse_yaml(configured(&format!("alpn: [{oversized}]")).as_bytes()).is_err()
        );
    }

    #[test]
    fn validates_simplified_vless_settings() {
        for yaml in [
            CURRENT_TLS.replace("server: 203.0.113.1", "server: 'bad host'"),
            CURRENT_TLS.replace("port: 443", "port: 0"),
            CURRENT_TLS.replace(
                "uuid: 00000000-0000-4000-8000-000000000001",
                "uuid: 00000000000040008000000000000001",
            ),
            CURRENT_TLS.replace("encryption: none", "encryption: auto"),
            CURRENT_TLS.replace("flow: \"\"", "flow: xtls-rprx-vision"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
        assert!(
            Config::parse_yaml(
                CURRENT_TLS
                    .replace("encryption: none", "encryption: \"\"")
                    .as_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn validates_flat_vless_transport_combinations() {
        for yaml in [
            CURRENT_TLS.replace("network: xhttp", "network: ws"),
            CURRENT_TLS.replace("tls: true", "tls: false"),
            CURRENT_TLS.replace(
                "    network: xhttp",
                "    security: tls\n    network: xhttp",
            ),
            CURRENT_TLS.replace("    xhttp-opts:\n", "    xhttp-opts: null\n"),
            CURRENT_TLS.replace(
                "    xhttp-opts:\n",
                "    reality-opts: null\n    xhttp-opts:\n",
            ),
            reality_yaml().replace("    reality-opts:\n", "    reality-opts: {}\n"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn validates_tls_and_xhttp_whitelists() {
        for yaml in [
            CURRENT_TLS.replace("alpn: [h2]", "alpn: [unknown]"),
            CURRENT_TLS.replace(
                "    alpn: [h2]",
                "    alpn: [h2]\n    skip-cert-verify: null",
            ),
            CURRENT_TLS.replace("    alpn: [h2]", "    alpn: [h2]\n    allowInsecure: true"),
            CURRENT_TLS.replace("path: /x", "path: '/bad path'"),
            CURRENT_TLS.replace("host: example.com", "host: '[broken'"),
            CURRENT_TLS.replace("host: example.com", "host: null"),
            CURRENT_TLS.replace("      path: /x", "      max-concurrency: 8\n      path: /x"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn validates_reality_key_and_short_id() {
        for yaml in [
            reality_yaml().replace(&URL_SAFE_NO_PAD.encode([7_u8; 32]), "not-base64url"),
            reality_yaml().replace("short-id: 01a2", "short-id: abc"),
            reality_yaml().replace("short-id: 01a2", "short-id: 0123456789abcdef00"),
            reality_yaml().replace("short-id: 01a2", "short-id: zz"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_non_json_yaml_features() {
        for yaml in [
            CURRENT_TLS.replacen("proxies:\n", "1: value\nproxies:\n", 1),
            CURRENT_TLS.replace("name: proxy", "name: !custom proxy"),
            CURRENT_TLS.replace("    xhttp-opts:\n", "    xhttp-opts: *defaults\n"),
            CURRENT_TLS.replacen("proxies:\n", "proxies: []\nproxies:\n", 1),
            format!("{CURRENT_TLS}\n---\n{CURRENT_TLS}"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }

        let quoted_anchor = CURRENT_TLS.replace("path: /x", "path: \"/&proxy\"");
        assert!(Config::parse_yaml(quoted_anchor.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_invalid_utf8_and_oversize_input() {
        assert!(Config::parse_yaml(&[0xff]).is_err());
        assert!(Config::parse_yaml(&vec![b'a'; MAX_CONFIG_BYTES + 1]).is_err());
    }

    #[test]
    fn parses_and_normalizes_current_config() {
        let yaml = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
tun:
  enable: true
  mtu: 1500
dns:
  enable: true
  ipv6: false
  nameserver:
    - 1.1.1.1
    - udp://[2001:db8::1]:5353
    - tcp://8.8.8.8
    - tcp://[::1]
rules:
  - domain,Example.COM.,DIRECT
  - DOMAIN-SUFFIX,example.cn,DIRECT
  - DOMAIN-KEYWORD,Tracker,REJECT
  - GEOSITE,GEOLOCATION-!CN,REJECT
  - GEOIP,CN,DIRECT,no-resolve
  - IP-CIDR,192.168.1.42/24,DIRECT,no-resolve
  - IP-CIDR6,2001:db8::1/64,DIRECT
  - DST-PORT,25/100-110,REJECT
  - NETWORK,udp,proxy
  - MATCH,proxy"#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();

        assert_eq!(config.proxies[0].tag, "proxy");
        assert_eq!(config.inbounds.len(), 2);
        assert!(matches!(
            &config.inbounds[..],
            [
                InboundConfig::Mixed(MixedInboundConfig {
                    access: ProxyAccess {
                        bind_address: None,
                        allow_lan: false,
                        ipv6: true
                    },
                    port: 1080,
                    ..
                }),
                InboundConfig::Tun(TunInboundConfig { mtu: 1500, .. })
            ]
        ));
        let InboundConfig::Mixed(mixed) = &config.inbounds[0] else {
            unreachable!("first inbound is the normalized mixed listener");
        };
        assert!(mixed.auth.as_ref().unwrap().matches(b"measure", b"secret"));

        assert_eq!(config.mixed_port, Some(1080));
        assert_eq!(
            config.tun,
            TunConfig {
                enable: true,
                mtu: 1500,
                ..TunConfig::default()
            }
        );
        assert!(!config.dns.ipv6);
        assert_eq!(
            config.dns.nameservers,
            [
                DnsNameserver {
                    path: None,
                    http_auth: None,
                    options: Default::default(),
                    transport: DnsTransport::Udp,
                    address: "1.1.1.1".parse().unwrap(),
                    port: 53,
                    route: DnsRoute::Direct,
                },
                DnsNameserver {
                    path: None,
                    http_auth: None,
                    options: Default::default(),
                    transport: DnsTransport::Udp,
                    address: "2001:db8::1".parse().unwrap(),
                    port: 5353,
                    route: DnsRoute::Direct,
                },
                DnsNameserver {
                    path: None,
                    http_auth: None,
                    options: Default::default(),
                    transport: DnsTransport::Tcp,
                    address: "8.8.8.8".parse().unwrap(),
                    port: 53,
                    route: DnsRoute::Direct,
                },
                DnsNameserver {
                    path: None,
                    http_auth: None,
                    options: Default::default(),
                    transport: DnsTransport::Tcp,
                    address: "::1".parse().unwrap(),
                    port: 53,
                    route: DnsRoute::Direct,
                },
            ]
        );
        assert_eq!(
            config.rules[0],
            RuleSpec {
                kind: RuleKind::Domain("example.com".to_owned()),
                action: RuleAction::Direct,
                no_resolve: false,
            }
        );
        assert_eq!(
            config.rules[3].kind,
            RuleKind::GeoSite("geolocation-!cn".to_owned())
        );
        assert_eq!(
            config.rules[4],
            RuleSpec {
                kind: RuleKind::GeoIp("cn".to_owned()),
                action: RuleAction::Direct,
                no_resolve: true,
            }
        );
        assert_eq!(
            config.rules[5].kind,
            RuleKind::IpCidr(IpCidr {
                network: "192.168.1.0".parse().unwrap(),
                prefix_len: 24,
            })
        );
        assert_eq!(
            config.rules[6].kind,
            RuleKind::IpCidr(IpCidr {
                network: "2001:db8::".parse().unwrap(),
                prefix_len: 64,
            })
        );
        assert_eq!(
            config.rules[7].kind,
            RuleKind::DstPorts(vec![
                PortRange { start: 25, end: 25 },
                PortRange {
                    start: 100,
                    end: 110
                }
            ])
        );
        assert_eq!(config.rules[8].kind, RuleKind::Network(Network::Udp));
        assert_eq!(config.rules.last().unwrap().kind, RuleKind::Match);
    }

    #[test]
    fn documented_current_examples_stay_parseable() {
        Config::parse_yaml(include_bytes!("../../docs/config.yaml")).unwrap();
        Config::parse_yaml(include_bytes!("../../example/windows-uwp/demo.yaml")).unwrap();
    }

    #[test]
    fn current_rules_share_runtime_domain_normalization() {
        let yaml = current_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - DOMAIN,XN--WCVS22D1M.HK,DIRECT\n  - DOMAIN-SUFFIX,例子.中国,proxy\n  - MATCH,proxy",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let rules = &config.rules;
        assert_eq!(
            rules[0].kind,
            RuleKind::Domain("xn--wcvs22d1m.hk".to_owned())
        );
        assert_eq!(
            rules[1].kind,
            RuleKind::DomainSuffix("xn--fsqu00a.xn--fiqs8s".to_owned())
        );
    }

    #[test]
    fn linux_network_options_keep_borrowed_descriptor_ownership() {
        let config = Config::parse_yaml(b"tun:\n  enable: true\n  file-descriptor: 9\n  auto-route: false\n  auto-detect-interface: false\n").unwrap();
        assert_eq!(config.tun.file_descriptor, 9);
        assert!(!config.tun.auto_route);
        assert!(!config.tun.auto_detect_interface);
    }

    #[test]
    fn tun_config_uses_mihomo_defaults_and_zero_sentinels() {
        for fields in ["", "  mtu: 0\n  udp-timeout: 0"] {
            let yaml = current_yaml(&format!("tun:\n  enable: true\n{fields}"));
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert_eq!(
                config.tun,
                TunConfig {
                    enable: true,
                    ..TunConfig::default()
                }
            );
            assert_eq!(config.tun.mtu, 9000);
            assert_eq!(config.tun.udp_timeout, Duration::from_secs(300));
        }
    }

    #[test]
    fn tun_config_normalizes_config_owned_resources_and_dns_targets() {
        let yaml = current_yaml(
            "tun:\n  enable: true\n  mtu: 1400\n  file-descriptor: 23\n  device: host-tun\n  dns-hijack: [any:5353, 'tcp://192.0.2.53:5353', '[2001:db8::53]:53']\n  udp-timeout: 7",
        );
        let tun = Config::parse_yaml(yaml.as_bytes()).unwrap().tun;
        assert_eq!(tun.file_descriptor, 23);
        assert_eq!(tun.device, "host-tun");
        assert_eq!(tun.mtu, 1400);
        assert_eq!(tun.udp_timeout, Duration::from_secs(7));
        assert!(tun.hijacks_dns("[2001:db8::1]:53".parse().unwrap()));
        assert!(tun.hijacks_dns("192.0.2.53:5353".parse().unwrap()));
        assert!(!tun.hijacks_dns("192.0.2.54:5353".parse().unwrap()));
        let disabled =
            Config::parse_yaml(current_yaml("tun:\n  enable: true\n  dns-hijack: []").as_bytes())
                .unwrap();
        assert!(!disabled.tun.hijacks_dns("1.1.1.1:53".parse().unwrap()));
    }

    #[test]
    fn tun_config_rejects_invalid_values_and_unimplemented_mihomo_fields() {
        for fields in [
            "mtu: 1279",
            "mtu: 65536",
            "file-descriptor: -1",
            "file-descriptor: 2147483648",
            "device: null",
            "device: \"bad\\nname\"",
            "udp-timeout: -1",
            "udp-timeout: null",
            "dns-hijack: [name.example:53]",
            "dns-hijack: null",
            "framing: rawIp",
            "auto-redirect: false",
            "stack: mips",
            "inet4-address: [198.18.0.1/30]",
            "gso: false",
        ] {
            let yaml = current_yaml(&format!("tun:\n  enable: true\n  {fields}"));
            assert!(
                Config::parse_yaml(yaml.as_bytes()).is_err(),
                "invalid TUN field accepted: {fields}"
            );
        }
    }

    #[test]
    fn current_config_defaults_disabled_dns_and_tun() {
        let config = Config::parse_yaml(
            current_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(config.ipv6);
        assert_eq!(
            config.tun,
            TunConfig {
                enable: false,
                ..TunConfig::default()
            }
        );
        assert_eq!(config.dns, DnsConfig::disabled().unwrap());
        assert_eq!(
            config.rules,
            [RuleSpec {
                kind: RuleKind::Match,
                action: RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap())),
                no_resolve: false,
            }]
        );
        assert_eq!(config.inbounds.len(), 1);

        let tun_only = Config::parse_yaml(current_yaml("tun:\n  enable: true").as_bytes()).unwrap();
        assert_eq!(tun_only.inbounds.len(), 1);
        assert!(matches!(tun_only.inbounds[0], InboundConfig::Tun(_)));
    }

    #[test]
    fn current_config_combines_global_and_dns_ipv6_switches() {
        let global_disabled = Config::parse_yaml(
            current_yaml(
                "ipv6: false\nmixed-port: 1080\nauthentication:\n  - measure:secret\ndns:\n  enable: true\n  ipv6: true\n  nameserver: [1.1.1.1]",
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(!global_disabled.ipv6);
        assert!(!global_disabled.dns.ipv6);

        let dns_disabled = Config::parse_yaml(
            current_yaml(
                "ipv6: true\nmixed-port: 1080\nauthentication:\n  - measure:secret\ndns:\n  enable: true\n  ipv6: false\n  nameserver: [1.1.1.1]",
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(dns_disabled.ipv6);
        assert!(!dns_disabled.dns.ipv6);
    }

    #[test]
    fn dns_ipv6_timeout_uses_milliseconds_and_zero_retains_the_default() {
        for (field, milliseconds) in [
            ("", 100),
            ("  ipv6-timeout: 0\n", 100),
            ("  ipv6-timeout: 37\n", 37),
        ] {
            let config = Config::parse_yaml(
                format!("mixed-port: 1080\ndns:\n  ipv6: true\n{field}").as_bytes(),
            )
            .unwrap();
            assert_eq!(config.dns.ipv6_timeout, Duration::from_millis(milliseconds));
        }
        assert!(Config::parse_yaml(b"mixed-port: 1080\ndns:\n  ipv6-timeout: -1\n").is_err());
    }

    #[test]
    fn dns_cache_max_size_uses_entries_and_zero_retains_the_default() {
        for (field, entries) in [
            ("", 4096),
            ("  cache-max-size: 0\n", 4096),
            ("  cache-max-size: 2\n", 2),
            ("  cache-max-size: 8192\n", 8192),
        ] {
            let config =
                Config::parse_yaml(format!("mixed-port: 1080\ndns:\n{field}").as_bytes()).unwrap();
            assert_eq!(config.dns.cache_max_size, entries);
        }
        assert!(Config::parse_yaml(b"mixed-port: 1080\ndns:\n  cache-max-size: -1\n").is_err());
    }

    #[test]
    fn dns_cache_algorithm_activates_arc_only_for_the_exact_name() {
        for (field, algorithm) in [
            ("", DnsCacheAlgorithm::Lru),
            ("  cache-algorithm: lru\n", DnsCacheAlgorithm::Lru),
            ("  cache-algorithm: arc\n", DnsCacheAlgorithm::Arc),
            ("  cache-algorithm: ARC\n", DnsCacheAlgorithm::Lru),
            ("  cache-algorithm: other\n", DnsCacheAlgorithm::Lru),
        ] {
            let config =
                Config::parse_yaml(format!("mixed-port: 1080\ndns:\n{field}").as_bytes()).unwrap();
            assert_eq!(config.dns.cache_algorithm, algorithm);
        }
    }

    #[test]
    fn current_config_requires_valid_references() {
        for yaml in [
            current_yaml("tun:\n  enable: true\n  mtu: 1279"),
            current_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret\ntypo: true",
            ),
            current_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("    alpn: [h2]", "    alpn: [h2]\n    allowInsecure: false"),
            CURRENT_TLS.replace("MATCH,proxy", "MATCH,PROXY"),
            CURRENT_TLS.replace("MATCH,proxy", "MATCH,unknown"),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let missing_proxy = "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,proxy\n";
        assert!(Config::parse_yaml(missing_proxy.as_bytes()).is_err());
        let empty_proxies = "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,proxy\nproxies: []\n";
        assert!(Config::parse_yaml(empty_proxies.as_bytes()).is_err());
        assert!(
            Config::parse_yaml(
                two_proxy_yaml(
                    "mixed-port: 1080
authentication:
  - measure:secret"
                )
                .as_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn parses_strict_socks5_settings_and_utf8_credentials() {
        let yaml = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-hop",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(1).unwrap()))
        );
        let ProxyProtocol::Socks5(socks5) = &config.proxies[1].protocol else {
            panic!("expected SOCKS5 proxy");
        };
        assert_eq!(socks5.address, "socks.example.com");
        assert_eq!(socks5.port, 1080);
        assert_eq!(socks5.username.as_deref(), Some("user"));
        assert_eq!(socks5.password.as_deref(), Some("password"));

        let no_auth = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replace("    username: user\n    password: password\n", "");
        let config = Config::parse_yaml(no_auth.as_bytes()).unwrap();
        let ProxyProtocol::Socks5(socks5) = &config.proxies[1].protocol else {
            panic!("expected SOCKS5 proxy");
        };
        assert_eq!(
            (socks5.username.as_ref(), socks5.password.as_ref()),
            (None, None)
        );

        let username = "用".repeat(85);
        let password = "密".repeat(85);
        let utf8 = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replace("username: user", &format!("username: '{username}'"))
        .replace("password: password", &format!("password: '{password}'"));
        assert!(Config::parse_yaml(utf8.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_invalid_socks5_settings() {
        let oversized = "a".repeat(256);
        for yaml in [
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("    password: password\n", ""),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("    username: user\n", ""),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("username: user", "username: ''"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("password: password", "password: ''"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("username: user", "username: null"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("password: password", "password: null"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("type: socks5", "type: socks"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("username: user", &format!("username: '{oversized}'")),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("    port: 1080", "    port: 0"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("server: socks.example.com", "server: 'bad host'"),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace(
                "    server: socks.example.com",
                "    typo: true\n    server: socks.example.com",
            ),
            two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace(
                "    server: socks.example.com",
                "    streamSettings: {}\n    server: socks.example.com",
            ),
        ] {
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn resolves_default_rules_tags_and_dialer_proxy_graph() {
        let yaml = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - DOMAIN-SUFFIX,example.com,proxy\n  - NETWORK,UDP,socks-hop\n  - MATCH,socks-hop",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: socks-hop\n    server: edge.example.com\n",
            1,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let first = ProxyId::new(0).unwrap();
        let second = ProxyId::new(1).unwrap();
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(second))
        );
        assert_eq!(
            config.proxies[0].dialer_proxy,
            Some(RouteTargetId::Proxy(second))
        );
        assert_eq!(config.proxies[1].dialer_proxy, None);
        let direct = Config::parse_yaml(
            yaml.replace("dialer-proxy: socks-hop", "dialer-proxy: DIRECT")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(direct.proxies[0].dialer_proxy, None);
        let default = Config::parse_yaml(
            yaml.replace("dialer-proxy: socks-hop", "dialer-proxy: \"\"")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(default.proxies[0].dialer_proxy, None);
        assert_eq!(
            config.rules[0].action,
            RuleAction::Route(RouteTargetId::Proxy(first))
        );
        assert_eq!(
            config.rules[1].action,
            RuleAction::Route(RouteTargetId::Proxy(second))
        );
        assert_eq!(
            config.rules[2].action,
            RuleAction::Route(RouteTargetId::Proxy(second))
        );

        let proxy_default = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        );
        let config = Config::parse_yaml(proxy_default.as_bytes()).unwrap();
        assert_eq!(
            config.rules,
            [RuleSpec {
                kind: RuleKind::Match,
                action: RuleAction::Route(RouteTargetId::Proxy(first)),
                no_resolve: false,
            }]
        );
    }

    #[test]
    fn normalizes_select_groups_in_declaration_order() {
        let yaml = with_proxy_groups(
            r#"  - name: 主线路
    type: select
    proxies: [proxy, 备用线路, DIRECT, REJECT, proxy]
    default-selected: 备用线路
  - name: 备用线路
    type: select
    proxies: [proxy, proxy, DIRECT]
    default-selected: proxy"#,
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#主线路"]
rules:
  - DOMAIN-SUFFIX,example.com,备用线路
  - MATCH,主线路"#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let main = ProxyGroupId::new(0).unwrap();
        let backup = ProxyGroupId::new(1).unwrap();

        assert_eq!(config.proxy_groups.len(), 3);
        assert_eq!(config.proxy_groups[0].name, "主线路");
        assert_eq!(config.proxy_groups[0].initial_member, 1);
        assert_eq!(
            config.proxy_groups[0]
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["proxy", "备用线路", "DIRECT", "REJECT", "proxy"]
        );
        assert_eq!(
            config.proxy_groups[0].members[1].target,
            ProxyGroupMemberTarget::Route(RouteTargetId::Group(backup))
        );
        assert_eq!(
            config.proxy_groups[0].members[2].target,
            ProxyGroupMemberTarget::Direct
        );
        assert_eq!(
            config.proxy_groups[0].members[3].target,
            ProxyGroupMemberTarget::Reject
        );
        assert_eq!(config.proxy_groups[1].initial_member, 0);
        assert_eq!(
            config.proxy_groups[1]
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["proxy", "proxy", "DIRECT"]
        );
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Group(main))
        );
        assert_eq!(
            config.rules[0].action,
            RuleAction::Route(RouteTargetId::Group(backup))
        );
        assert_eq!(
            config.dns.nameservers[0].route,
            DnsRoute::Route(RouteTargetId::Group(main))
        );
    }

    #[test]
    fn strictly_rejects_invalid_select_group_shapes_and_graphs() {
        let fields =
            "mixed-port: 1080\nauthentication:\n  - measure:secret\nrules:\n  - MATCH,主线路";
        for groups in [
            r#"  - name: 主线路
    type: select
    proxies: []"#,
            r#"  - name: 主线路
    type: select
    proxies: [missing]"#,
            r#"  - name: 主线路
    type: select
    proxies: [RULES]"#,
        ] {
            let yaml = with_proxy_groups(groups, fields);
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let cycle = with_proxy_groups(
            r#"  - name: 主线路
    type: select
    proxies: [备用线路]
  - name: 备用线路
    type: select
    proxies: [主线路]"#,
            fields,
        );
        let error = Config::parse_yaml(cycle.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("circular member dependency"));

        let duplicate = with_proxy_groups(
            r#"  - name: 主线路
    type: select
    proxies: [proxy]
  - name: 主线路
    type: select
    proxies: [DIRECT]"#,
            fields,
        );
        assert!(Config::parse_yaml(duplicate.as_bytes()).is_err());

        let shared_name = with_proxy_groups(
            r#"  - name: proxy
    type: select
    proxies: [DIRECT]"#,
            "mixed-port: 1080\nauthentication:\n  - measure:secret\nrules:\n  - MATCH,proxy",
        );
        assert!(Config::parse_yaml(shared_name.as_bytes()).is_err());

        let null_groups = current_yaml("mixed-port: 1080\nauthentication:\n  - measure:secret")
            .replacen("\nproxies:", "\nproxy-groups: null\nproxies:", 1);
        assert!(Config::parse_yaml(null_groups.as_bytes()).is_err());
    }

    #[test]
    fn rejects_mixed_dialer_cycles_and_secures_group_controller() {
        let groups = r#"  - name: 主线路
    type: select
    proxies: [proxy, DIRECT]"#;
        let dialer_group = with_proxy_groups(
            groups,
            "mixed-port: 1080\nauthentication:\n  - measure:secret\nrules:\n  - MATCH,主线路",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: 主线路\n    server: edge.example.com\n",
            1,
        );
        let error = Config::parse_yaml(dialer_group.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("circular dialer-proxy"),
            "{error}"
        );
        let direct_group = dialer_group.replace("proxies: [proxy, DIRECT]", "proxies: [DIRECT]");
        assert_eq!(
            Config::parse_yaml(direct_group.as_bytes()).unwrap().proxies[0].dialer_proxy,
            Some(RouteTargetId::Group(ProxyGroupId::new(0).unwrap()))
        );

        let no_controller = with_proxy_groups(
            groups,
            "mixed-port: 1080\nauthentication:\n  - measure:secret\nrules:\n  - MATCH,主线路",
        );
        assert!(Config::parse_yaml(no_controller.as_bytes()).is_ok());

        let controller = with_proxy_groups(
            groups,
            "mixed-port: 1080\nauthentication:\n  - measure:secret\nexternal-controller: '127.0.0.1:19090'\nsecret: token\nrules:\n  - MATCH,主线路",
        );
        assert!(Config::parse_yaml(controller.as_bytes()).is_ok());

        let missing_secret = controller.replace("secret: token\n", "");
        let config = Config::parse_yaml(missing_secret.as_bytes()).unwrap();
        assert!(config.external_controller.unwrap().secret.is_none());
    }

    #[test]
    fn accepts_many_proxies_and_resolves_rule_and_dns_tags() {
        let yaml = format!(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver:
    - 1.1.1.1#node-0
    - 8.8.8.8#node-1
    - 9.9.9.9#node-2
    - 4.4.4.4#node-3
rules:
  - DOMAIN,one.example,node-1
  - DOMAIN,two.example,node-2
  - MATCH,node-3
proxies:
{}"#,
            socks_proxy_entries(4, false)
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();

        assert_eq!(config.proxies.len(), 4);
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::from_index(3)))
        );
        assert_eq!(
            config
                .dns
                .nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::from_index(0))),
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::from_index(1))),
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::from_index(2))),
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::from_index(3))),
            ]
        );
        assert_eq!(
            config
                .rules
                .iter()
                .map(|rule| rule.action)
                .collect::<Vec<_>>(),
            [
                RuleAction::Route(RouteTargetId::Proxy(ProxyId::from_index(1))),
                RuleAction::Route(RouteTargetId::Proxy(ProxyId::from_index(2))),
                RuleAction::Route(RouteTargetId::Proxy(ProxyId::from_index(3))),
            ]
        );
    }

    #[test]
    fn validates_long_proxy_chains_beyond_u8_indices() {
        let entries = socks_proxy_entries(300, true);
        let yaml = format!(
            "mixed-port: 1080\nauthentication:\n  - measure:secret\n\
             rules:\n  - MATCH,node-299\nproxies:\n{entries}"
        );
        assert!(yaml.len() <= MAX_CONFIG_BYTES);
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 300);
        assert_eq!(
            config.rules.last().unwrap().action,
            RuleAction::Route(RouteTargetId::Proxy(ProxyId::from_index(299)))
        );
        assert_eq!(
            config.proxies[299].dialer_proxy,
            Some(RouteTargetId::Proxy(ProxyId::new(298).unwrap()))
        );

        let cycle_entries = entries.replacen(
            "    type: socks5\n",
            "    type: socks5\n    dialer-proxy: node-299\n",
            1,
        );
        let cycle = format!(
            "mixed-port: 1080\nauthentication:\n  - measure:secret\n\
             rules:\n  - MATCH,node-299\nproxies:\n{cycle_entries}"
        );
        let error = Config::parse_yaml(cycle.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("circular dialer-proxy"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_proxy_tags_references_and_cycles() {
        for tag in [
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "COMPATIBLE",
            "PASS",
            "PASS-RULE",
        ] {
            let yaml = CURRENT_TLS.replace("name: proxy", &format!("name: '{tag}'"));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
        for tag in [
            "RULES", "edge,one", "edge#one", "edge/one", "edge?one", "edge%one", ".", "..",
            " edge", "edge ",
        ] {
            let yaml = CURRENT_TLS
                .replace("name: proxy", &format!("name: '{tag}'"))
                .replace("MATCH,proxy", "MATCH,DIRECT");
            assert!(Config::parse_yaml(yaml.as_bytes()).is_ok(), "{tag}");
        }
        let tag = "a".repeat(256);
        let yaml = CURRENT_TLS
            .replace("name: proxy", &format!("name: '{tag}'"))
            .replace("MATCH,proxy", &format!("MATCH,{tag}"));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_ok());

        let duplicate = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replace("name: socks-hop", "name: proxy");
        assert!(Config::parse_yaml(duplicate.as_bytes()).is_err());

        let unknown = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: unknown\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(unknown.as_bytes()).is_err());

        for invalid_reference in ["null", "'bad#name'"] {
            let yaml = two_proxy_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replacen(
                "    server: edge.example.com\n",
                &format!("    dialer-proxy: {invalid_reference}\n    server: edge.example.com\n"),
                1,
            );
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let self_reference = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: proxy\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(self_reference.as_bytes()).is_err());

        let cycle = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: socks-hop\n    server: edge.example.com\n",
            1,
        )
        .replace(
            "  - name: socks-hop\n    type: socks5\n    server:",
            "  - name: socks-hop\n    type: socks5\n    dialer-proxy: proxy\n    server:",
        );
        assert!(Config::parse_yaml(cycle.as_bytes()).is_err());
    }

    #[test]
    fn accepts_all_two_hop_protocol_combinations() {
        let vless_socks = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret",
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: socks-hop\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(vless_socks.as_bytes()).is_ok());

        let socks_vless = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-hop",
        )
        .replace(
            "  - name: socks-hop\n    type: socks5\n    server:",
            "  - name: socks-hop\n    type: socks5\n    dialer-proxy: proxy\n    server:",
        );
        assert!(Config::parse_yaml(socks_vless.as_bytes()).is_ok());

        let vless_vless = format!(
            "{}{}",
            current_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret"
            ),
            second_vless_entry()
        )
        .replacen(
            "    server: edge.example.com\n",
            "    dialer-proxy: vless-two\n    server: edge.example.com\n",
            1,
        );
        assert!(Config::parse_yaml(vless_vless.as_bytes()).is_ok());

        let first_socks = SOCKS_PROXY_ENTRY
            .replace("name: socks-hop", "name: socks-one")
            .replace("server: socks.example.com", "server: first.example.com")
            .replace(
                "    server: first.example.com\n",
                "    dialer-proxy: socks-hop\n    server: first.example.com\n",
            );
        let socks_socks = format!(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-one\nproxies:\n{first_socks}{SOCKS_PROXY_ENTRY}"
        );
        assert!(Config::parse_yaml(socks_socks.as_bytes()).is_ok());
    }

    #[test]
    fn current_config_validates_dns_upstreams_and_roles() {
        let config = Config::parse_yaml(b"mixed-port: 1080\ndns: {enable: true}\n").unwrap();
        assert!(!config.dns.ipv6);
        assert_eq!(config.dns.nameservers[0].transport, DnsTransport::Https);
        assert_eq!(
            config.dns.nameservers[1].address,
            DnsAddress::Ip("223.5.5.5".parse().unwrap())
        );
        for dns in [
            "{enable: true, nameserver: []}",
            "{default-nameserver: [dns.example]}",
            "{nameserver: ['tls://1.1.1.1:0']}",
            "{respect-rules: true}",
        ] {
            assert!(
                Config::parse_yaml(format!("mixed-port: 1080\ndns: {dns}\n").as_bytes()).is_err()
            );
        }
        let config = Config::parse_yaml(b"mixed-port: 1080\ndns: {enable: false, nameserver: ['udp://dns.example', 'https://dns.example/query'], enhanced-mode: redir-host}\n").unwrap();
        assert!(!config.dns.enable);
    }

    #[test]
    fn dns_source_aliases_preserve_mihomo_roles_and_bootstrap_rules() {
        for alias in ["system", "system://", "dhcp://system"] {
            let yaml = format!(
                "mixed-port: 1080\ndns:\n  enable: true\n  default-nameserver: ['{alias}']\n  nameserver: ['{alias}#unknown']\n  fallback: ['{alias}']\n  proxy-server-nameserver: ['{alias}']\n  direct-nameserver: ['{alias}']\n  nameserver-policy: {{example.com: '{alias}'}}\n"
            );
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            for server in config
                .dns
                .default_nameservers
                .iter()
                .chain(&config.dns.nameservers)
                .chain(&config.dns.fallback.nameservers)
                .chain(&config.dns.proxy_nameservers)
                .chain(&config.dns.direct_nameservers)
                .chain(config.dns.nameserver_policies[0].nameservers.iter())
            {
                assert_eq!(server.address, DnsAddress::Source(DnsSource::System));
                assert_eq!(server.route, DnsRoute::Direct);
            }
        }
        let parsed = Config::parse_yaml(
            b"mixed-port: 1080\ndns: {nameserver: ['dhcp://physical0#unknown']}\n",
        )
        .unwrap();
        assert_eq!(
            parsed.dns.nameservers[0].address,
            DnsAddress::Source(DnsSource::Dhcp("physical0".into()))
        );
        for invalid in ["dhcp://", "dhcp://physical0/", "system://physical0"] {
            let yaml = format!("mixed-port: 1080\ndns: {{nameserver: ['{invalid}']}}\n");
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
        assert!(
            Config::parse_yaml(
                b"mixed-port: 1080\ndns: {default-nameserver: ['dhcp://physical0']}\n"
            )
            .is_err()
        );
    }

    #[test]
    fn dns_rcode_nameserver_uses_the_mihomo_names_and_existing_policy_schema() {
        for (name, rcode) in [
            ("success", 0),
            ("format_error", 1),
            ("server_failure", 2),
            ("name_error", 3),
            ("not_implemented", 4),
            ("refused", 5),
        ] {
            let yaml = format!(
                "mixed-port: 1080\ndns:\n  enable: true\n  nameserver: [rcode://{name}]\n  nameserver-policy:\n    example.com: rcode://{name}\n"
            );
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert_eq!(
                config.dns.nameservers[0].transport,
                DnsTransport::Rcode(rcode)
            );
            assert_eq!(
                config.dns.nameserver_policies[0].nameservers[0].transport,
                DnsTransport::Rcode(rcode)
            );
        }
        for endpoint in ["rcode://NXDOMAIN", "rcode://6", "rcode://success:53"] {
            let yaml = format!("mixed-port: 1080\ndns:\n  nameserver: [{endpoint}]\n");
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err());
        }
        assert!(
            Config::parse_yaml(
                b"mixed-port: 1080\ndns:\n  default-nameserver: [rcode://success]\n"
            )
            .is_err()
        );
    }

    #[test]
    fn current_config_normalizes_dns_nameserver_routes() {
        let yaml = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - udp://[2001:db8::1]:5353#DIRECT
    - tcp://8.8.8.8#RULES
    - tcp://[::1]#proxy"#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let dns = &config.dns;
        assert_eq!(
            dns.nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Direct,
                DnsRoute::Direct,
                DnsRoute::Rules,
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap())),
            ]
        );

        let yaml = current_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [udp://1.1.1.1:53#PROXY]",
        );
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let yaml = current_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [udp://1.1.1.1:53#PROXY]",
        )
        .replace("name: proxy", "name: PROXY")
        .replace("MATCH,proxy", "MATCH,PROXY");
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config.dns.nameservers[0].route,
            DnsRoute::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap()))
        );

        let yaml = two_proxy_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,socks-hop\ndns:\n  enable: true\n  nameserver: [8.8.8.8#proxy, 9.9.9.9#socks-hop, 4.4.4.4#RULES]",
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config
                .dns
                .nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap())),
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::new(1).unwrap())),
                DnsRoute::Rules,
            ]
        );
    }

    #[test]
    fn accepts_builtin_final_actions_without_static_proxies() {
        for proxies in ["", "proxies: []\n"] {
            for (target, action) in [
                ("DIRECT", RuleAction::Direct),
                ("REJECT", RuleAction::Reject),
            ] {
                let yaml = format!("mixed-port: 1080\n{proxies}rules: ['MATCH,{target}']\n");
                let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
                assert!(config.proxies.is_empty());
                assert_eq!(config.rules.last().unwrap().action, action);
                assert_eq!(config.rules[0].action, action);
            }
        }
        let config = Config::parse_yaml(b"mixed-port: 1080\nproxy-groups:\n  - name: local\n    type: select\n    proxies: [DIRECT, REJECT]\nrules: ['MATCH,local']\n").unwrap();
        assert!(config.proxies.is_empty());
        assert_eq!(
            config.proxy_groups[0].members[0].target,
            ProxyGroupMemberTarget::Direct
        );
    }

    #[test]
    fn rejects_deprecated_fallback_filter_geosite() {
        for enable in [false, true] {
            let yaml = format!(
                "rules: ['MATCH,DIRECT']\ndns:\n  enable: {enable}\n  fallback-filter:\n    geosite: []\n"
            );
            let error = Config::parse_yaml(yaml.as_bytes()).unwrap_err();
            assert!(error.to_string().contains("geosite"), "{error}");
        }
    }

    #[test]
    fn current_config_parses_ordered_geosite_nameserver_policies() {
        let yaml = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#proxy"]
  nameserver-policy:
    "geosite:APPLE,CN":
      - "tcp://223.5.5.5:53#DIRECT"
    "geosite:private":
      - "udp://192.0.2.53:5353"
      - "tcp://198.51.100.53:53#proxy""#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let dns = config.dns;
        assert_eq!(
            dns.nameservers[0].route,
            DnsRoute::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap()))
        );
        assert_eq!(dns.nameserver_policies.len(), 2);
        assert_eq!(dns.nameserver_policies[0].geosite_codes(), ["apple", "cn"]);
        assert_eq!(
            dns.nameserver_policies[0].nameservers.as_ref(),
            [DnsNameserver {
                path: None,
                http_auth: None,
                options: Default::default(),
                transport: DnsTransport::Tcp,
                address: "223.5.5.5".parse().unwrap(),
                port: 53,
                route: DnsRoute::Direct,
            }]
        );
        assert_eq!(dns.nameserver_policies[1].geosite_codes(), ["private"]);
        assert_eq!(
            dns.nameserver_policies[1]
                .nameservers
                .iter()
                .map(|nameserver| nameserver.route)
                .collect::<Vec<_>>(),
            [
                DnsRoute::Direct,
                DnsRoute::Route(RouteTargetId::Proxy(ProxyId::new(0).unwrap()))
            ]
        );
    }

    #[test]
    fn current_config_parses_geodata_attributes_and_inversion() {
        let yaml = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    "geosite:GOOGLE@ads@CN,!GOOGLE@ads": ["tcp://223.5.5.5"]
rules:
  - GEOSITE,!GOOGLE@CN@ADS@cn,DIRECT
  - GEOSITE,geolocation-!cn,DIRECT
  - GEOIP,!CN,DIRECT,no-resolve
  - MATCH,proxy"#,
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            config.rules[0].kind,
            RuleKind::GeoSite("!google@ads@cn".to_owned())
        );
        assert_eq!(
            config.rules[1].kind,
            RuleKind::GeoSite("geolocation-!cn".to_owned())
        );
        assert_eq!(config.rules[2].kind, RuleKind::GeoIp("!cn".to_owned()));
        assert!(config.rules[2].no_resolve);
        assert_eq!(
            config.dns.nameserver_policies[0].geosite_codes(),
            ["google@ads@cn", "!google@ads"]
        );
    }

    #[test]
    fn current_config_strictly_validates_nameserver_policy_schema_and_limits() {
        for policy in [
            r#"    "rule-set:cn": ["tcp://223.5.5.5"]"#,
            r#"    "example.com": null"#,
            r#"    "example.com": {server: 1.1.1.1}"#,
            r#"    "example.com": [false]"#,
            r#"    "foo..example": "1.1.1.1""#,
            r#"    "foo.*bar.example": "1.1.1.1""#,
            r#"    "foo.+.example": "1.1.1.1""#,
            r#"    "example.com.": "1.1.1.1""#,
            r#"    "example.com,": "1.1.1.1""#,
            r#"    "geosite:": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:cn,": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:cn, apple": ["tcp://223.5.5.5"]"#,
            r#"    "geosite:cn": []"#,
        ] {
            let yaml = current_yaml(&format!(
                "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n{policy}"
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let duplicate = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    "geosite:CN": ["tcp://223.5.5.5"]
    "geosite:cn": ["tcp://8.8.8.8"]"#,
        );
        assert_eq!(
            Config::parse_yaml(duplicate.as_bytes())
                .unwrap()
                .dns
                .nameserver_policies
                .len(),
            2
        );

        let many_codes = (0..=16)
            .map(|index| format!("code{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let yaml = current_yaml(&format!(
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n    \"geosite:{many_codes}\": [tcp://223.5.5.5]"
        ));
        assert_eq!(
            Config::parse_yaml(yaml.as_bytes())
                .unwrap()
                .dns
                .nameserver_policies[0]
                .geosite_codes()
                .len(),
            17
        );

        let many_policies = (0..=16)
            .map(|index| format!("    \"geosite:code{index}\": [tcp://223.5.5.5]"))
            .collect::<Vec<_>>()
            .join("\n");
        let yaml = current_yaml(&format!(
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n{many_policies}"
        ));
        assert_eq!(
            Config::parse_yaml(yaml.as_bytes())
                .unwrap()
                .dns
                .nameserver_policies
                .len(),
            17
        );

        let disabled = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: false
  nameserver-policy:
    "geosite:cn": ["tcp://223.5.5.5"]"#,
        );
        assert!(Config::parse_yaml(disabled.as_bytes()).is_ok());

        let missing_main = current_yaml(
            r#"mixed-port: 1080
authentication:
  - measure:secret
dns:
  enable: true
  nameserver-policy:
    "geosite:cn": ["tcp://223.5.5.5"]"#,
        );
        assert!(Config::parse_yaml(missing_main.as_bytes()).is_ok());
    }

    #[test]
    fn current_config_strictly_rejects_invalid_dns_route_fragments() {
        for nameserver in [
            "udp://1.1.1.1:53#bad%00interface",
            "udp://1.1.1.1:53#unknown-option=true",
        ] {
            let yaml = current_yaml(&format!(
                "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  nameserver: [\"{nameserver}\"]"
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        for reserved_tag in ["DIRECT", "REJECT", "RULES"] {
            let yaml = current_yaml(
                "mixed-port: 1080
authentication:
  - measure:secret",
            )
            .replace("  - name: proxy\n", &format!("  - name: {reserved_tag}\n"));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn current_config_rejects_removed_dns_switches() {
        for fields in [
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  enhanced-mode: normal\n  nameserver: [1.1.1.1]",
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  respect-rules: true\n  nameserver: [1.1.1.1]",
            "mixed-port: 1080
authentication:
  - measure:secret\ndns:\n  enable: true\n  respectRules: false\n  nameserver: [1.1.1.1]",
        ] {
            let yaml = current_yaml(fields);
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }
    }

    #[test]
    fn current_config_rejects_invalid_rule_shapes_and_ordering() {
        for rules in [
            "  - DOMAIN,example.com,BLOCK\n  - MATCH,proxy",
            "  - DOMAIN,example.com,unknown\n  - MATCH,proxy",
            "  - DOMAIN,example.com,DIRECT,no-resolve\n  - MATCH,proxy",
            "  - GEOIP,CN,DIRECT,NO-RESOLVE\n  - MATCH,proxy",
            "  - GEOIP,CN@ads,DIRECT\n  - MATCH,proxy",
            "  - GEOSITE,!,DIRECT\n  - MATCH,proxy",
            "  - GEOSITE,@ads,DIRECT\n  - MATCH,proxy",
            "  - IP-CIDR,192.0.2.0/33,DIRECT\n  - MATCH,proxy",
            "  - NETWORK,ICMP,REJECT\n  - MATCH,proxy",
            "  - MATCH,PROXY\n  - DOMAIN,example.com,DIRECT",
            "  - MATCH,PROXY\n  - MATCH,DIRECT",
        ] {
            let yaml = current_yaml(&format!(
                "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n{rules}"
            ));
            assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
        }

        let explicit_empty = current_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules: []",
        );
        assert!(Config::parse_yaml(explicit_empty.as_bytes()).is_ok());

        let non_ascii_whitespace = current_yaml(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - MATCH,\u{a0}PROXY",
        );
        assert!(Config::parse_yaml(non_ascii_whitespace.as_bytes()).is_err());
    }

    #[test]
    fn current_config_enforces_rule_count_and_byte_limits() {
        let too_many = (0..=MAX_RULES)
            .map(|_| "  - NETWORK,TCP,proxy\n")
            .collect::<String>();
        let yaml = current_yaml(&format!(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n{too_many}  - MATCH,proxy"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let oversized = "a".repeat(MAX_RULE_BYTES + 1);
        let yaml = current_yaml(&format!(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n  - {oversized}\n  - MATCH,proxy"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err());

        let keyword = "a".repeat(240);
        let many_rules = (0..600)
            .map(|_| format!("  - DOMAIN-KEYWORD,{keyword},proxy\n"))
            .collect::<String>();
        let yaml = current_yaml(&format!(
            "mixed-port: 1080
authentication:
  - measure:secret\nrules:\n{many_rules}  - MATCH,proxy"
        ));
        assert!(Config::parse_yaml(yaml.as_bytes()).is_ok());
    }
}

/// Global physical TCP policy. YAML keeps Mihomo's top-level field names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionSettings {
    pub tcp_concurrent: bool,
    pub keep_alive_idle: i32,
    pub keep_alive_interval: i32,
    pub disable_keep_alive: bool,
}
