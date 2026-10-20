//! IP4P physical-endpoint representation used by Mihomo's resolver/dialer.
use super::ConnectionSettings;
use std::net::{Ipv4Addr, SocketAddr};

impl ConnectionSettings {
    /// Decode an explicitly enabled IP4P endpoint without allocation. Logical
    /// host/port, TLS authentication and proxy-chain destinations stay separate.
    /// This must not be applied to connectionless DIRECT business datagrams.
    #[must_use]
    pub fn convert_ip4p_endpoint(self, address: SocketAddr) -> SocketAddr {
        if self.dialer_ip4p_convert
            && let SocketAddr::V6(encoded) = address
        {
            let bytes = encoded.ip().octets();
            if bytes[..4] == [0x20, 0x01, 0, 0] {
                return SocketAddr::from((
                    Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
                    u16::from_be_bytes([bytes[10], bytes[11]]),
                ));
            }
        }
        address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    #[test]
    fn ip4p_exact_prefix_network_port_and_default_off() {
        let policy = ConnectionSettings {
            dialer_ip4p_convert: true,
            ..Default::default()
        };
        let encoded: SocketAddr = "[2001:0:1234:5678:9abc:1bb:c000:201]:8443".parse().unwrap();
        assert_eq!(
            policy.convert_ip4p_endpoint(encoded),
            "192.0.2.1:443".parse().unwrap()
        );
        assert_eq!(
            ConnectionSettings::default().convert_ip4p_endpoint(encoded),
            encoded
        );
        for (encoded, expected) in [
            ("[2001:0::0:0]:443", "0.0.0.0:0"),
            ("[2001:0::ffff:ffff:ffff]:9", "255.255.255.255:65535"),
            ("[2001:0::1:7f00:1]:443", "127.0.0.1:1"),
        ] {
            assert_eq!(
                policy.convert_ip4p_endpoint(encoded.parse().unwrap()),
                expected.parse().unwrap()
            );
        }
        for ordinary in [
            "192.0.2.1:443",
            "[2001:1::1]:443",
            "[2000:0::1]:443",
            "[::ffff:192.0.2.1]:443",
            "[fe80::1%7]:443",
        ] {
            let ordinary: SocketAddr = ordinary.parse().unwrap();
            assert_eq!(policy.convert_ip4p_endpoint(ordinary), ordinary);
        }
    }
    #[test]
    fn ip4p_configuration_is_strict_opt_in() {
        assert!(
            !Config::parse_yaml(b"rules: ['MATCH,DIRECT']")
                .unwrap()
                .connections
                .dialer_ip4p_convert
        );
        assert!(
            Config::parse_yaml(
                b"experimental: {dialer-ip4p-convert: true}\nrules: ['MATCH,DIRECT']"
            )
            .unwrap()
            .connections
            .dialer_ip4p_convert
        );
        for input in [
            "experimental: {dialer-ip4p-convert: 'true'}",
            "experimental: {unknown: true}",
        ] {
            assert!(Config::parse_yaml(input.as_bytes()).is_err(), "{input}");
        }
    }
}
