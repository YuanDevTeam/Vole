use super::invalid;
use crate::Result;

/// Sizes of receive credit. Neither value eagerly allocates a receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicReceiveWindow {
    pub initial: u64,
    pub maximum: u64,
}

impl QuicReceiveWindow {
    pub(super) fn normalize(initial: u64, maximum: u64, default: Self) -> Result<Self> {
        let initial = if initial == 0 {
            default.initial
        } else {
            initial
        };
        let maximum = if maximum == 0 {
            default.maximum
        } else {
            maximum
        };
        if initial > (1_u64 << 62) - 1 {
            return invalid("QUIC receive credit exceeds its wire representation");
        }
        // The reference clamps max values to QUIC VarInt without shrinking initial.
        Ok(Self {
            initial,
            maximum: maximum.min((1_u64 << 62) - 1),
        })
    }
}
