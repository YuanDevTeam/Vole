//! Public YAML normalization only; these cases do not initialize a runtime.

#[cfg(any(
    feature = "outbound-vless",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic",
    feature = "outbound-socks5"
))]
fn proxy(protocol: &str, fields: &str) -> super::ProxyConfig {
    let credentials = match protocol {
        "vless" => "uuid: 00000000-0000-4000-8000-000000000001\n    tls: true",
        "hysteria2" => "password: fixture",
        "tuic" => "uuid: 00000000-0000-4000-8000-000000000001\n    password: fixture",
        "socks5" => "",
        _ => unreachable!(),
    };
    let fields: String = fields.lines().map(|line| format!("    {line}\n")).collect();
    let yaml = format!(
        "proxies:\n  - name: edge\n    type: {protocol}\n    server: proxy.invalid\n    port: 443\n    {credentials}\n{fields}rules: ['MATCH,edge']\n"
    );
    let mut config = super::Config::parse_yaml(yaml.as_bytes()).unwrap();
    assert_eq!(config.proxies.len(), 1);
    config.proxies.remove(0)
}

#[cfg(feature = "outbound-vless")]
#[test]
fn vless_none_packet_encoding_normalizes_to_xudp() {
    let proxy = proxy("vless", "udp: true\npacket-encoding: none");
    let super::ProxyProtocol::Vless(vless) = proxy.protocol else {
        panic!("expected VLESS");
    };
    assert!(proxy.udp);
    assert_eq!(vless.packet_encoding, super::VlessPacketEncoding::Xudp);
}

#[cfg(feature = "outbound-vless")]
#[test]
fn vless_none_packet_encoding_preserves_vision() {
    for udp in [false, true] {
        let proxy = proxy(
            "vless",
            &format!("udp: {udp}\nflow: xtls-rprx-vision\npacket-encoding: none"),
        );
        let super::ProxyProtocol::Vless(vless) = proxy.protocol else {
            panic!("expected VLESS");
        };
        assert_eq!(proxy.udp, udp);
        assert_eq!(vless.flow, "xtls-rprx-vision");
        assert_eq!(vless.packet_encoding, super::VlessPacketEncoding::Xudp);
    }
}

#[cfg(feature = "outbound-vless")]
#[test]
fn vless_existing_packet_encodings_keep_their_normalized_values() {
    for (fields, expected) in [
        ("", super::VlessPacketEncoding::Xudp),
        ("packet-encoding: xudp", super::VlessPacketEncoding::Xudp),
        (
            "packet-encoding: packetaddr",
            super::VlessPacketEncoding::PacketAddr,
        ),
        (
            "packet-encoding: packet",
            super::VlessPacketEncoding::PacketAddr,
        ),
    ] {
        let proxy = proxy("vless", fields);
        let super::ProxyProtocol::Vless(vless) = proxy.protocol else {
            panic!("expected VLESS");
        };
        assert_eq!(vless.packet_encoding, expected, "{fields}");
    }
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
fn hysteria2_udp_capability_is_intrinsic() {
    for fields in ["", "udp: false", "udp: true"] {
        let proxy = proxy("hysteria2", fields);
        assert!(matches!(proxy.protocol, super::ProxyProtocol::Hysteria2(_)));
        assert!(proxy.udp, "Hysteria2 must support UDP with {fields:?}");
    }
}

#[cfg(feature = "outbound-tuic")]
#[test]
fn tuic_udp_capability_is_intrinsic() {
    for fields in ["", "udp: false", "udp: true"] {
        let proxy = proxy("tuic", fields);
        assert!(matches!(proxy.protocol, super::ProxyProtocol::Tuic(_)));
        assert!(proxy.udp, "TUIC must support UDP with {fields:?}");
    }
}

#[cfg(feature = "outbound-socks5")]
#[test]
fn socks5_udp_capability_keeps_its_explicit_opt_in() {
    for (fields, expected) in [("", false), ("udp: false", false), ("udp: true", true)] {
        let proxy = proxy("socks5", fields);
        assert!(matches!(proxy.protocol, super::ProxyProtocol::Socks5(_)));
        assert_eq!(proxy.udp, expected, "{fields}");
    }
}
