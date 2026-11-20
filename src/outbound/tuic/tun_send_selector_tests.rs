use super::tun_pending_send_enabled;
use crate::{config::TuicUdpMode, session::InboundKind};

#[test]
fn tun_pending_send_requires_actual_mac_tun_quic_without_uot() {
    assert!(tun_pending_send_enabled(
        true,
        InboundKind::Tun,
        TuicUdpMode::Quic,
        false
    ));
    assert!(!tun_pending_send_enabled(
        false,
        InboundKind::Tun,
        TuicUdpMode::Quic,
        false
    ));
    assert!(!tun_pending_send_enabled(
        true,
        InboundKind::Tun,
        TuicUdpMode::Native,
        false
    ));
    assert!(!tun_pending_send_enabled(
        true,
        InboundKind::Tun,
        TuicUdpMode::Quic,
        true
    ));
    for inbound in [
        InboundKind::Socks5,
        InboundKind::Http,
        InboundKind::Https,
        InboundKind::InternalDns,
        InboundKind::InternalGeoData,
        InboundKind::InternalMeasure,
    ] {
        assert!(!tun_pending_send_enabled(
            true,
            inbound,
            TuicUdpMode::Quic,
            false
        ));
    }
}
