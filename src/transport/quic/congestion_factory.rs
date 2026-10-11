//! Selection is confined to the new protocol consumers; the existing
//! Hysteria2/TUIC factories retain their own controller implementations.

use std::sync::Arc;

use quinn::congestion::ControllerFactory;

use super::congestion::{BbrConfigFactory, BbrVersion, LossConfigFactory};

/// Empty or unknown names preserve the transport's default, as in Mihomo.
/// CUBIC and NewReno do not consume the BBR window/profile fields.
pub fn congestion_controller(
    name: &str,
    cwnd: i64,
    profile: &str,
) -> Option<Arc<dyn ControllerFactory + Send + Sync>> {
    Some(match name {
        "cubic" => Arc::new(LossConfigFactory::new(false)),
        "new_reno" => Arc::new(LossConfigFactory::new(true)),
        "bbr_meta_v1" => Arc::new(BbrConfigFactory::new(BbrVersion::V1, cwnd, profile)),
        "bbr_meta_v2" | "bbr" => Arc::new(BbrConfigFactory::new(BbrVersion::V2, cwnd, profile)),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn quic_meta_factory_keeps_defaults_alias_and_window_units() {
        let now = Instant::now();
        assert!(congestion_controller("", 0, "").is_none());
        assert!(congestion_controller("unknown", 0, "").is_none());
        for name in ["cubic", "new_reno"] {
            for cwnd in [-1, 0, 100] {
                let controller = congestion_controller(name, cwnd, "conservative")
                    .unwrap()
                    .build(now, 1200);
                assert_eq!(controller.initial_window(), 32 * 1200);
                assert!(controller.pacing_policy().is_some());
            }
        }
        for name in ["bbr_meta_v2", "bbr"] {
            let controller = congestion_controller(name, 0, "standard")
                .unwrap()
                .build(now, 1200);
            assert_eq!(controller.initial_window(), 32 * 1200);
            let controller = congestion_controller(name, 40, "aggressive")
                .unwrap()
                .build(now, 1280);
            assert_eq!(controller.initial_window(), 40 * 1280);
        }
        let controller = congestion_controller("bbr_meta_v1", 0, "aggressive")
            .unwrap()
            .build(now, 1200);
        assert_eq!(controller.initial_window(), 32 * 1280);
    }
}
