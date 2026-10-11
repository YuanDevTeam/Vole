//! Logic for controlling the rate at which data is sent

use crate::connection::RttEstimator;
use crate::{Duration, Instant};
use std::any::Any;
use std::sync::Arc;

mod bbr;
mod cubic;
mod new_reno;

pub use crate::packet::SpaceId as PacketSpace;
pub use bbr::{Bbr, BbrConfig};
pub use cubic::{Cubic, CubicConfig};
pub use new_reno::{NewReno, NewRenoConfig};

/// Identifies one QUIC packet across all packet number spaces in a connection.
#[derive(Debug, Copy, Clone)]
pub struct PacketInfo {
    /// Monotonic connection-wide identifier, never reused on Retry or migration.
    pub sample_id: u64,
    /// Wire packet number within `space`.
    pub packet_number: u64,
    /// Packet number space.
    pub space: PacketSpace,
    /// Path on which this packet was sent.
    pub path_generation: u64,
    /// Time when the packet was committed to transmission.
    pub time_sent: Instant,
    /// Bytes counted against congestion control, excluding UDP/IP overhead.
    pub congestion_bytes: u64,
    /// Whether the packet elicits an acknowledgement.
    pub ack_eliciting: bool,
}

/// Why a tracked packet no longer contributes to a controller's sampler.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketFeedback {
    /// Actual delivery, confirmed by a peer ACK on the active validated path.
    Acked,
    /// A normal congestion loss on the active validated path.
    Lost,
    /// Forgotten, neutered, or belonging to another/unvalidated path.
    Discarded,
}

/// A complete ACK/loss event, delivered after RTT, loss and ECN processing.
#[derive(Debug, Copy, Clone, Default)]
pub struct FeedbackBatch {
    /// Congestion bytes in flight before the event.
    pub prior_in_flight: u64,
    /// Congestion bytes in flight after the event.
    pub in_flight: u64,
    /// Congestion bytes newly acknowledged during the event.
    pub acked_bytes: u64,
    /// Congestion bytes newly lost during the event.
    pub lost_bytes: u64,
    /// Congestion bytes abandoned without an ACK or congestion loss.
    pub discarded_bytes: u64,
    /// Largest newly acknowledged connection-wide sample identifier.
    pub largest_acked_sample_id: Option<u64>,
    /// Whether outgoing application data was limiting transmission.
    pub app_limited: bool,
    /// Whether this event supplied a new RTT measurement.
    pub rtt_updated: bool,
    /// Whether the event detected persistent congestion.
    pub persistent_congestion: bool,
    /// Whether verified ECN counters reported congestion.
    pub ecn_congestion: bool,
}

/// An optional explicit token-bucket policy for packet transmission.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PacingPolicy {
    /// Token refill rate in bytes per second; controllers should return at least one.
    pub rate_bytes_per_second: u64,
    /// Maximum token balance, in bytes; at least one current MTU is retained.
    pub burst_bytes: u64,
    /// Minimum delay when a packet requires more tokens.
    pub min_delay: Duration,
}

/// Common interface for different congestion controllers
pub trait Controller: Send + Sync {
    /// Enables optional packet-level callbacks. This capability is cached per path.
    ///
    /// Existing controllers leave this disabled and retain their original callbacks.
    fn packet_feedback_enabled(&self) -> bool {
        false
    }

    /// One packet was sent. `prior_in_flight` excludes this packet's bytes.
    #[allow(unused_variables)]
    fn on_packet_sent(&mut self, packet: PacketInfo, prior_in_flight: u64, app_limited: bool) {}

    /// One packet was acknowledged, lost, or abandoned. Samplers must forget
    /// discarded packets without recording delivery or congestion loss.
    #[allow(unused_variables)]
    fn on_packet_feedback(&mut self, now: Instant, packet: PacketInfo, feedback: PacketFeedback) {}

    /// Completes a packet-level event after its RTT, ACK, loss and ECN changes.
    #[allow(unused_variables)]
    fn on_feedback_end(&mut self, now: Instant, batch: FeedbackBatch, rtt: &RttEstimator) {}

    /// Supplies explicit pacing. `None` preserves Quinn's original window/RTT pacer.
    fn pacing_policy(&self) -> Option<PacingPolicy> {
        None
    }

    /// One or more packets were just sent
    #[allow(unused_variables)]
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {}

    /// Packet deliveries were confirmed
    ///
    /// `app_limited` indicates whether the connection was blocked on outgoing
    /// application data prior to receiving these acknowledgements.
    #[allow(unused_variables)]
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
    }

    /// Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has completed.
    #[allow(unused_variables)]
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
    }

    /// Packets were deemed lost or marked congested
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    /// `lost_bytes` indicates how many bytes were lost. This value will be 0 for ECN triggers.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    );

    /// The known MTU for the current network path has been updated
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Retrieve implementation-specific metrics used to populate `qlog` traces when they are enabled
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
        }
    }

    /// Duplicate the controller's model for a new path.
    ///
    /// Controllers using packet-level feedback must clear outstanding sampler
    /// entries in the clone: packets already sent remain owned by the old path.
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Initial congestion window
    fn initial_window(&self) -> u64;

    /// Returns Self for use in down-casting to extract implementation details
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Common congestion controller metrics
#[derive(Default)]
#[non_exhaustive]
pub struct ControllerMetrics {
    /// Congestion window (bytes)
    pub congestion_window: u64,
    /// Slow start threshold (bytes)
    pub ssthresh: Option<u64>,
    /// Pacing rate (bits/s)
    pub pacing_rate: Option<u64>,
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller>;
}

const BASE_DATAGRAM_SIZE: u64 = 1200;
