//! Mihomo TrustTunnel node settings, separate from the shared TLS policy.
use super::{
    ProxyProtocol, TlsCertificatePolicy, TlsConfig, deserialize_present_option, invalid,
    validate_host, validate_port,
};
use crate::Result;
use serde::Deserialize;

#[derive(Clone, PartialEq, Eq)]
pub struct TrustTunnelOutboundConfig {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: TlsConfig,
    pub udp: bool,
    pub quic: bool,
    pub health_check: bool,
    pub pool: TrustTunnelPoolOptions,
    pub congestion_controller: String,
}

impl std::fmt::Debug for TrustTunnelOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustTunnelOutboundConfig")
            .field("udp", &self.udp)
            .field("quic", &self.quic)
            .field("health_check", &self.health_check)
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}

/// Pool thresholds retain their signs: negative values disable the matching
/// positive threshold without opting into the literal all-zero defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustTunnelPoolOptions {
    pub max_connections: i64,
    pub min_streams: i64,
    pub max_streams: i64,
}

impl Default for TrustTunnelPoolOptions {
    fn default() -> Self {
        Self {
            max_connections: 8,
            min_streams: 5,
            max_streams: 0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawTrustTunnel {
    name: String,
    server: String,
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    udp: bool,
    #[serde(default)]
    quic: bool,
    #[serde(default)]
    health_check: bool,
    #[serde(default)]
    max_connections: i64,
    #[serde(default)]
    min_streams: i64,
    #[serde(default)]
    max_streams: i64,
    #[serde(default)]
    congestion_controller: String,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sni: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(default, deserialize_with = "super::ech::deserialize")]
    ech_opts: Option<super::ech::RawEch>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    client_fingerprint: Option<String>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    certificate: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    private_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    dialer_proxy: Option<String>,
}

impl std::fmt::Debug for RawTrustTunnel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawTrustTunnel")
            .finish_non_exhaustive()
    }
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<RawTrustTunnel, D::Error> {
    RawTrustTunnel::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid TrustTunnel configuration fields"))
}

impl RawTrustTunnel {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-trusttunnel") {
            return invalid("TrustTunnel outbound support is disabled at build time");
        }
        validate_host(&self.server, "TrustTunnel server")?;
        validate_port(self.port, "TrustTunnel")?;
        let server_name = self
            .sni
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| self.server.clone());
        validate_host(&server_name, "TrustTunnel sni")?;
        let required_alpn = if self.quic { b"h3" } else { b"h2" };
        let mut alpn: Vec<Vec<u8>> = self
            .alpn
            .unwrap_or_default()
            .into_iter()
            .map(String::into_bytes)
            .collect();
        if alpn.is_empty() {
            alpn.push(required_alpn.to_vec());
        }
        if alpn
            .iter()
            .any(|value| value.is_empty() || value.len() > 255)
            || alpn.iter().map(|value| value.len() + 1).sum::<usize>() > 65_533
            || !alpn.iter().any(|value| value == required_alpn)
        {
            return invalid("TrustTunnel ALPN must include its selected HTTP version");
        }
        // Mihomo's QUIC path converts the policy to standard TLS without
        // applying the TCP ClientHello template or validating its name.
        let client_fingerprint = if self.quic {
            None
        } else {
            super::parse_client_fingerprint(self.client_fingerprint.as_deref())?
        };
        let ech = self
            .ech_opts
            .map(|raw| raw.normalize(client_fingerprint.is_some()))
            .transpose()?
            .flatten();
        if ech.is_some() && server_name.parse::<std::net::IpAddr>().is_ok() {
            return invalid("TrustTunnel ECH requires DNS sni");
        }
        let pool = if self.max_connections == 0 && self.min_streams == 0 && self.max_streams == 0 {
            TrustTunnelPoolOptions::default()
        } else {
            TrustTunnelPoolOptions {
                max_connections: self.max_connections,
                min_streams: self.min_streams,
                max_streams: self.max_streams,
            }
        };
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::TrustTunnel(TrustTunnelOutboundConfig {
                address: self.server,
                port: self.port,
                username: self.username,
                password: self.password,
                tls: TlsConfig {
                    server_name,
                    alpn,
                    tls13_only: self.quic || ech.is_some(),
                    required_alpn: Some(required_alpn.to_vec()),
                    ech,
                    client_fingerprint,
                    certificate: TlsCertificatePolicy {
                        skip_cert_verify: self.skip_cert_verify,
                        fingerprint: super::normalize_certificate_fingerprint(
                            self.fingerprint.as_deref(),
                        )?,
                        verification_name: super::normalize_verification_name(
                            self.name_cert_verify,
                        )?,
                    },
                    identity: super::normalize_client_identity(self.certificate, self.private_key)?,
                },
                udp: self.udp,
                quic: self.quic,
                health_check: self.health_check,
                pool,
                congestion_controller: self.congestion_controller,
            }),
        ))
    }
}

#[cfg(all(test, feature = "outbound-trusttunnel"))]
mod tests {
    use super::*;
    use crate::config::{Config, IpVersion};

    fn parse(options: &str) -> Result<Config> {
        Config::parse_yaml(
            format!(
                "proxies:\n  - name: edge\n    type: trusttunnel\n    server: cover.invalid\n    port: 443\n{options}"
            )
            .as_bytes(),
        )
    }

    fn node(config: &Config) -> &TrustTunnelOutboundConfig {
        let ProxyProtocol::TrustTunnel(node) = &config.proxies[0].protocol else {
            panic!("expected TrustTunnel node")
        };
        node
    }

    #[test]
    fn h2_defaults_and_empty_auth_keep_mihomo_semantics() {
        for options in [
            "",
            "    alpn: []\n    sni: ''\n    username: ''\n    password: ''\n",
        ] {
            let config = parse(options).unwrap();
            let node = node(&config);
            assert_eq!(node.tls.server_name, "cover.invalid");
            assert_eq!(node.tls.alpn, [b"h2".to_vec()]);
            assert_eq!(node.tls.required_alpn.as_deref(), Some(b"h2".as_slice()));
            assert_eq!(node.pool, TrustTunnelPoolOptions::default());
            assert!(node.username.is_empty() && node.password.is_empty());
            assert!(!config.proxies[0].udp && !node.udp && !node.quic && !node.health_check);
        }
    }

    #[test]
    fn pool_thresholds_preserve_mixed_fields_and_signs() {
        let config = parse(
            "    max-connections: 2\n    min-streams: -3\n    max-streams: 4\n    ip-version: ipv4-prefer\n",
        )
        .unwrap();
        assert_eq!(
            node(&config).pool,
            TrustTunnelPoolOptions {
                max_connections: 2,
                min_streams: -3,
                max_streams: 4,
            }
        );
        assert_eq!(config.proxies[0].ip_version, IpVersion::Ipv4Prefer);
        let config = parse("    max-connections: -1\n").unwrap();
        assert_eq!(node(&config).pool.max_connections, -1);
        assert_eq!(node(&config).pool.min_streams, 0);
    }

    #[test]
    fn h2_tls_options_do_not_leak_credentials() {
        let config = parse(
            "    username: synthetic-user\n    password: synthetic-password\n    sni: cover-name.invalid\n    alpn: [h2, http/1.1]\n    skip-cert-verify: true\n    name-cert-verify: verified.invalid\n    fingerprint: 'abababababababababababababababababababababababababababababababab'\n    congestion-controller: arbitrary-unused-h2-value\n",
        )
        .unwrap();
        let node = node(&config);
        assert_eq!(node.tls.server_name, "cover-name.invalid");
        assert_eq!(
            node.tls.certificate.verification_name.as_deref(),
            Some("verified.invalid")
        );
        assert!(node.tls.certificate.skip_cert_verify);
        assert_eq!(node.tls.certificate.fingerprint, Some([0xab; 32]));
        let debug = format!("{config:?}");
        assert!(!debug.contains("synthetic-user") && !debug.contains("synthetic-password"));
    }

    #[test]
    fn h2_requires_its_alpn_and_forwards_udp_and_health_check() {
        assert!(parse("    alpn: [http/1.1]\n").is_err());
        let config = parse("    udp: true\n    health-check: true\n").unwrap();
        assert!(config.proxies[0].udp && node(&config).udp && node(&config).health_check);
    }

    #[test]
    fn h3_defaults_force_http3_and_preserve_transport_independent_udp() {
        for extra in ["", "    alpn: []\n    sni: ''\n"] {
            let config = parse(&format!("    quic: true\n{extra}")).unwrap();
            let node = node(&config);
            assert!(node.quic && node.tls.tls13_only);
            assert_eq!(node.tls.alpn, [b"h3".to_vec()]);
            assert_eq!(node.tls.required_alpn.as_deref(), Some(b"h3".as_slice()));
            assert_eq!(node.tls.server_name, "cover.invalid");
            assert!(!node.udp && !config.proxies[0].udp);
            assert!(node.username.is_empty() && node.password.is_empty());
        }
        let config =
            parse("    quic: true\n    udp: true\n    health-check: true\n    alpn: [h3, h2]\n")
                .unwrap();
        assert!(config.proxies[0].udp && node(&config).udp && node(&config).health_check);
        assert_eq!(node(&config).tls.alpn, [b"h3".to_vec(), b"h2".to_vec()]);
        for options in [
            "    quic: true\n    alpn: [h2]\n",
            "    quic: true\n    alpn: ['']\n",
        ] {
            assert!(parse(options).is_err());
        }
    }

    #[test]
    fn h3_does_not_consume_tcp_fingerprint_or_add_congestion_restrictions() {
        for fingerprint in ["chrome", "none", "unknown-http3-noop", ""] {
            let config = parse(&format!("    quic: true\n    client-fingerprint: '{fingerprint}'\n    congestion-controller: arbitrary-default\n    max-connections: -3\n    min-streams: -4\n")).unwrap();
            let node = node(&config);
            assert!(node.tls.client_fingerprint.is_none());
            assert_eq!(node.congestion_controller, "arbitrary-default");
            assert_eq!(node.pool.max_connections, -3);
            assert_eq!(node.pool.min_streams, -4);
        }
        assert!(parse("    client-fingerprint: unknown-http3-noop\n").is_err());
        for value in ["null", "[]", "1"] {
            assert!(
                parse(&format!(
                    "    quic: true\n    client-fingerprint: {value}\n"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn removed_quic_tuning_fields_are_rejected_in_both_modes() {
        for quic in [false, true] {
            for field in ["cwnd: 16", "bbr-profile: standard"] {
                assert!(parse(&format!("    quic: {quic}\n    {field}\n")).is_err());
            }
        }
    }

    #[test]
    fn h3_shares_certificate_and_dynamic_ech_policy() {
        let config = parse("    quic: true\n    sni: cover-name.invalid\n    client-fingerprint: unknown-http3-noop\n    skip-cert-verify: true\n    name-cert-verify: verified.invalid\n    fingerprint: 'abababababababababababababababababababababababababababababababab'\n    ech-opts:\n      enable: true\n      query-server-name: ech-query.invalid\n").unwrap();
        let node = node(&config);
        assert_eq!(node.tls.server_name, "cover-name.invalid");
        assert_eq!(
            node.tls.certificate.verification_name.as_deref(),
            Some("verified.invalid")
        );
        assert!(node.tls.certificate.skip_cert_verify);
        assert_eq!(node.tls.certificate.fingerprint, Some([0xab; 32]));
        assert!(node.tls.ech.is_some());
        assert!(node.tls.client_fingerprint.is_none());
    }
}
