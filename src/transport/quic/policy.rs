//! Receive credit expressed using only official Quinn transport APIs.
use crate::config::QuicReceiveWindow;

/// These policies use fixed receive credit, without adaptive windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveWindowPolicy {
    /// Keep the normalized initial credit for the connection's lifetime.
    Initial,
    /// Authorize the larger normalized initial/maximum credit from startup.
    Maximum,
    /// Use bounded intermediate stream credit and initial aggregate credit.
    Middle,
}

/// Default fixed receive-credit strategy for protocol outbounds.
pub const RECEIVE_WINDOW_POLICY: ReceiveWindowPolicy = ReceiveWindowPolicy::Middle;

const MIDDLE_STREAM_CREDIT: u64 = 4 * 1024 * 1024;

impl ReceiveWindowPolicy {
    fn stream_credit(self, window: QuicReceiveWindow) -> u64 {
        match self {
            Self::Initial => window.initial,
            Self::Maximum => window.initial.max(window.maximum),
            Self::Middle => window.initial.max(window.maximum.min(MIDDLE_STREAM_CREDIT)),
        }
    }

    fn connection_credit(self, window: QuicReceiveWindow) -> u64 {
        match self {
            Self::Maximum => window.initial.max(window.maximum),
            Self::Initial | Self::Middle => window.initial,
        }
    }
}

/// Configure independent fixed per-stream and aggregate receive credit.
///
/// The caller supplies normalized, wire-representable sizes. Credit bounds
/// unread data; it does not eagerly allocate a payload buffer of that size.
pub fn configure_receive_windows(
    transport: &mut quinn::TransportConfig,
    stream: QuicReceiveWindow,
    connection: QuicReceiveWindow,
    policy: ReceiveWindowPolicy,
) -> std::io::Result<()> {
    let wire = |credit| {
        quinn::VarInt::from_u64(credit)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    };
    transport
        .stream_receive_window(wire(policy.stream_credit(stream))?)
        .receive_window(wire(policy.connection_credit(connection))?);
    Ok(())
}

/// Payload capacity for a canonically encoded DATAGRAM with a length field.
/// Received payload validation cannot recover the peer's actual frame encoding.
pub(crate) fn datagram_payload_limit(frame_limit: u16) -> usize {
    let limit = usize::from(frame_limit);
    // Limits currently stop at 1400, so the length uses one or two bytes.
    if limit <= 65 {
        limit.saturating_sub(2).min(63)
    } else {
        limit.saturating_sub(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_variants_preserve_independent_normalized_bounds() {
        let stream = QuicReceiveWindow {
            initial: 10,
            maximum: 100,
        };
        let connection = QuicReceiveWindow {
            initial: 300,
            maximum: 200,
        };
        assert_eq!(ReceiveWindowPolicy::Initial.stream_credit(stream), 10);
        assert_eq!(ReceiveWindowPolicy::Maximum.stream_credit(stream), 100);
        for policy in [
            ReceiveWindowPolicy::Initial,
            ReceiveWindowPolicy::Maximum,
            ReceiveWindowPolicy::Middle,
        ] {
            assert_eq!(policy.connection_credit(connection), 300);
            configure_receive_windows(
                &mut quinn::TransportConfig::default(),
                stream,
                connection,
                policy,
            )
            .unwrap();
        }
        assert!(
            configure_receive_windows(
                &mut quinn::TransportConfig::default(),
                QuicReceiveWindow {
                    initial: 1 << 62,
                    maximum: 1
                },
                connection,
                ReceiveWindowPolicy::Maximum,
            )
            .is_err()
        );
    }

    #[test]
    fn middle_window_bounds_stream_credit_without_expanding_aggregate() {
        let policy = ReceiveWindowPolicy::Middle;
        let mib = 1024 * 1024;
        let tuic_stream = QuicReceiveWindow {
            initial: 15 * mib / 10,
            maximum: 15 * mib,
        };
        let tuic_connection = QuicReceiveWindow {
            initial: 64 * mib / 10,
            maximum: 64 * mib,
        };
        assert_eq!(policy.stream_credit(tuic_stream), 4 * mib);
        assert_eq!(policy.connection_credit(tuic_connection), 64 * mib / 10);
        for (initial, maximum, expected) in [
            (mib, 2 * mib, 2 * mib),
            (8 * mib, 8 * mib, 8 * mib),
            (7 * mib, 3 * mib, 7 * mib),
            (5 * mib, 5 * mib, 5 * mib),
        ] {
            let window = QuicReceiveWindow { initial, maximum };
            assert_eq!(policy.stream_credit(window), expected);
            assert_eq!(policy.connection_credit(window), initial);
        }
        let error = configure_receive_windows(
            &mut quinn::TransportConfig::default(),
            tuic_stream,
            QuicReceiveWindow {
                initial: 1 << 62,
                maximum: 1,
            },
            policy,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn canonical_datagram_capacity_accounts_for_varint_boundary() {
        for (frame, payload) in [
            (0, 0),
            (1, 0),
            (2, 0),
            (3, 1),
            (65, 63),
            (66, 63),
            (67, 64),
            (80, 77),
            (1281, 1278),
            (1400, 1397),
        ] {
            assert_eq!(datagram_payload_limit(frame), payload);
        }
    }
}
