use crate::{Result, VoleError};

/// Fairness bound for control/discard work in one poll or receive iteration.
pub const IO_POLL_BUDGET: usize = 32;

/// One retained plaintext chunk while the official SS codec is backpressured.
pub const SHADOWSOCKS_WRITE_CHUNK: usize = 16 * 1024;

/// Per-object VLESS bounds, never business-flow admission limits.
pub const VLESS_UDP_FRAME_BYTES: usize = 65537;
pub const VISION_CONTENT_BYTES: usize = 8192 - 21;
pub const VISION_TLS_RECORD_BYTES: usize = 18 * 1024;
pub const VISION_HELLO_BYTES: usize = 65536;
pub const GRPC_IDLE_CONNECTIONS: usize = 4;
pub const GRPC_PING_TIMEOUT_SECONDS: usize = 15;

/// XHTTP and sing-mux per-object parser, queue and retained-pool bounds.
pub const XHTTP_CUSTOM_HEADER_BYTES: usize = 8 * 1024;
pub const XHTTP_CUSTOM_HEADERS: usize = 100;
pub const XHTTP_PADDING_BYTES: usize = 4096;
pub const XHTTP_POST_BYTES: usize = 16 * 1024 * 1024;
pub const XHTTP_PACKET_BATCH_BYTES: usize = 64 * 1024;
pub const XHTTP_REQUEST_BYTES: usize = 16 * 1024;
pub const XHTTP_REQUEST_HEADERS: usize = 128;
pub const XHTTP_IDLE_ENTRIES: usize = 64;
pub const XHTTP_IDLE_H1_CONNECTIONS: usize = 4;
pub const XHTTP_ACTIVE_H2_LEASES: usize = 4;
pub const XHTTP_ACTIVE_H3_LEASES: usize = 4;
pub const XHTTP_BODY_QUEUE: usize = 2;
pub const XHTTP_BODY_CHUNK: usize = 16 * 1024;
pub const XHTTP_H3_UNI_STREAMS: usize = 8;
pub const XHTTP_H3_STREAM_WINDOW: usize = 64 * 1024;
pub const XHTTP_H3_CONNECTION_WINDOW: usize = 128 * 1024;
pub const XHTTP_H3_SEND_WINDOW: usize = 64 * 1024;
pub const SING_MUX_IDLE_CONNECTIONS: usize = 16;
pub const SING_MUX_COMMAND_QUEUE: usize = 16;
pub const SING_MUX_CHUNK: usize = 16 * 1024;
pub const SMUX_RECEIVE_QUEUE: usize = 4;
/// Retire the physical connection after this many admissions, without closing
/// existing streams. Never pass a saturated connection to yamux's open method.
pub const YAMUX_CONNECTION_ADMISSIONS: usize = 64;
pub const YAMUX_CONNECTION_WINDOW: usize = YAMUX_CONNECTION_ADMISSIONS * 256 * 1024;

/// Hysteria2 per-packet, per-association and per-connection retained bounds.
pub const HY2_UDP_PAYLOAD: usize = 4096;
pub const HY2_UDP_QUEUE: usize = 32;
pub const HY2_SUBMISSION_QUEUE: usize = 32;
pub const HY2_AUTH_SESSIONS: usize = 2;
pub const HY2_PENDING_PACKETS: usize = 64;
pub const HY2_PENDING_BYTES: usize = 256 * 1024;
pub const HY2_FRAGMENT_TTL_SECONDS: usize = 5;
pub const HY2_PATH_RETIRE_SECONDS: usize = 1;
pub const HY2_QUIC_PAYLOAD: usize = 1400;
pub const HY2_UNI_STREAMS: usize = 8;
pub const HY2_SEND_WINDOW: usize = 1024 * 1024;
pub const HY2_DATAGRAM_SEND_BUFFER: usize = 4 * 1024 * 1024;
pub const HY2_DATAGRAM_RECEIVE_BUFFER: usize = 2 * 1024 * 1024;
pub const HY2_AUTH_HEADERS: usize = 16384;
pub const HY2_RESPONSE_MESSAGE: usize = 2048;
pub const HY2_RESPONSE_PADDING: usize = 4096;
pub const TUIC_QUIC_PAYLOAD: usize = 1400;
pub const TUIC_CONTROL_READERS: usize = 32;
pub const TUIC_SEND_WINDOW: usize = 1024 * 1024;
pub const TUIC_DATAGRAM_BUFFER: usize = 256 * 1024;
pub const TUIC_UDP_QUEUE: usize = 32;
pub const TUIC_PENDING_PACKETS: usize = 64;
pub const TUIC_PENDING_BYTES: usize = 256 * 1024;
pub const TUIC_FRAGMENT_TTL_SECONDS: usize = 5;
pub const TUIC_FIN_GRACE_SECONDS: usize = 5;

/// Process observation ceiling, never lifecycle admission.
pub const MEMORY_OBSERVATION_CEILING_BYTES: u64 = 45 * 1024 * 1024;

/// 1 Gbps process observation threshold, never lifecycle admission.
pub const MEMORY_OBSERVATION_1GBPS_BYTES: u64 = 43 * 1024 * 1024;

/// Fixed stack used by each bootstrap resolver worker.
pub(crate) const DNS_WORKER_STACK_BYTES: usize = 512 * 1024;
/// Process-wide ceiling for lazily created bootstrap resolver workers.
pub(crate) const MAX_DNS_WORKERS: usize = 4;

/// Unfinished physical socket setup jobs per lifecycle owner, shared by TCP
/// and UDP. Callers wait for submission capacity; established connections are
/// not counted and receive no business-concurrency quota.
pub(crate) const MAX_SOCKET_INITIALIZATIONS: usize = 4;

/// Retained-memory, queue and per-object safety boundaries.
///
/// These values deliberately do not cap concurrent TCP sessions, UDP
/// associations, half-open TCP flows, outbound handshakes or DNS queries.
/// Runtime concurrency follows actual workload; bounded queues, per-flow
/// buffers, caches and operation timeouts keep individual retained objects
/// controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub packet_queue_capacity: usize,
    pub event_queue_capacity: usize,
    /// Maximum datagram accepted by local SOCKS5/mixed inbounds.
    pub max_datagram_size: usize,
    /// Maximum raw IP packet accepted by a TUN netstack.
    pub tun_max_datagram_size: usize,
    pub tcp_buffer_per_direction: usize,
    /// Explicit low-level DNS constructor override. Production sessions use
    /// dns.cache-max-size for the shared typed/opaque result capacity instead.
    pub dns_address_cache_entries: usize,
    /// Retained address-to-domain hints used by redir-host routing.
    pub dns_redir_host_entries: usize,
    /// Pending request datagrams retained by each ordinary TUN UDP association.
    pub tun_udp_association_queue_capacity: usize,
    /// Bounded burst headroom for ordinary TUN UDP responses waiting for the
    /// shared packet writer. Saturation drops only the current response.
    pub tun_udp_response_queue_capacity: usize,
    /// Reserved TUN DNS response capacity. The isolated response path consumes
    /// this value once that path is enabled.
    pub tun_dns_response_queue_capacity: usize,
    pub tls_buffer_limit: usize,
    pub xhttp_send_buffer_size: usize,
    pub xhttp_upload_chunk_size: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            packet_queue_capacity: 256,
            event_queue_capacity: 128,
            max_datagram_size: 65_535,
            tun_max_datagram_size: 1_500,
            tcp_buffer_per_direction: 32 * 1024,
            dns_address_cache_entries: 256,
            dns_redir_host_entries: 256,
            tun_udp_association_queue_capacity: 64,
            tun_udp_response_queue_capacity: 256,
            tun_dns_response_queue_capacity: 128,
            tls_buffer_limit: 64 * 1024,
            xhttp_send_buffer_size: 64 * 1024,
            xhttp_upload_chunk_size: 64 * 1024,
        }
    }
}

impl ResourceLimits {
    pub fn validate(self) -> Result<Self> {
        for (name, value) in [
            ("packet_queue_capacity", self.packet_queue_capacity),
            ("event_queue_capacity", self.event_queue_capacity),
            ("max_datagram_size", self.max_datagram_size),
            ("tun_max_datagram_size", self.tun_max_datagram_size),
            ("tcp_buffer_per_direction", self.tcp_buffer_per_direction),
            ("dns_address_cache_entries", self.dns_address_cache_entries),
            ("dns_redir_host_entries", self.dns_redir_host_entries),
            (
                "tun_udp_association_queue_capacity",
                self.tun_udp_association_queue_capacity,
            ),
            (
                "tun_udp_response_queue_capacity",
                self.tun_udp_response_queue_capacity,
            ),
            (
                "tun_dns_response_queue_capacity",
                self.tun_dns_response_queue_capacity,
            ),
            ("tls_buffer_limit", self.tls_buffer_limit),
            ("xhttp_send_buffer_size", self.xhttp_send_buffer_size),
            ("xhttp_upload_chunk_size", self.xhttp_upload_chunk_size),
        ] {
            if value == 0 {
                return Err(VoleError::ResourceLimit {
                    resource: name,
                    limit: value,
                });
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_sized_limits_are_rejected() {
        let invalid = [
            ResourceLimits {
                packet_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_max_datagram_size: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tcp_buffer_per_direction: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                dns_address_cache_entries: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                dns_redir_host_entries: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_udp_association_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_udp_response_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tun_dns_response_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                tls_buffer_limit: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                xhttp_send_buffer_size: 0,
                ..ResourceLimits::default()
            },
            ResourceLimits {
                xhttp_upload_chunk_size: 0,
                ..ResourceLimits::default()
            },
        ];
        assert!(invalid.into_iter().all(|limits| limits.validate().is_err()));
    }

    #[test]
    fn default_profile_keeps_queue_cache_and_per_object_boundaries() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.packet_queue_capacity, 256);
        assert_eq!(limits.event_queue_capacity, 128);
        assert_eq!(limits.max_datagram_size, 65_535);
        assert_eq!(limits.tun_max_datagram_size, 1_500);
        assert_eq!(limits.tcp_buffer_per_direction, 32 * 1024);
        assert_eq!(limits.dns_address_cache_entries, 256);
        assert_eq!(limits.dns_redir_host_entries, 256);
        assert_eq!(limits.tun_udp_association_queue_capacity, 64);
        assert_eq!(limits.tun_udp_response_queue_capacity, 256);
        assert_eq!(limits.tun_dns_response_queue_capacity, 128);
        assert_eq!(limits.tls_buffer_limit, 64 * 1024);
        assert_eq!(limits.xhttp_send_buffer_size, 64 * 1024);
        assert_eq!(limits.xhttp_upload_chunk_size, 64 * 1024);
    }
}
