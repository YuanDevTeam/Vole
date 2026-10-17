use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use thiserror::Error;

/// Configured source addresses for an active raw-IP client stack.
///
/// An omitted family is unavailable; the driver never invents a source address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientAddresses {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// Finite buffering and timing configuration for one netstack instance.
///
/// Queue counts are hard limits. Each TCP buffer includes both the smoltcp
/// socket buffer and the application-facing queue for one flow in that
/// direction. Each layer is bounded to half of the configured total.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetStackConfig {
    /// Maximum raw IP packet size and the IP-medium MTU advertised to smoltcp.
    pub mtu: usize,
    /// Raw packet count in each TUN direction.
    pub packet_queue: usize,
    /// Accepted TCP streams waiting for the dispatcher.
    pub tcp_accept_queue: usize,
    /// UDP datagrams waiting for the dispatcher.
    pub udp_queue: usize,
    /// Total receive bytes per TCP flow, from raw IP to `TcpStream::AsyncRead`.
    ///
    /// Must be even and at least 4096 bytes, split equally between smoltcp and
    /// the application-facing receive queue.
    pub tcp_recv_buffer: usize,
    /// Total send bytes per TCP flow, from `TcpStream::AsyncWrite` to raw IP.
    ///
    /// Must be even and at least 4096 bytes, split equally between smoltcp and
    /// the application-facing send queue.
    pub tcp_send_buffer: usize,
    /// Inactive TCP socket timeout enforced by smoltcp.
    pub tcp_idle_timeout: Duration,
    /// Maximum delay before the driver polls sockets again.
    pub max_poll_interval: Duration,
    /// Locally answer ICMPv4/ICMPv6 echo requests received from TUN.
    ///
    /// This is disabled by default for generic netstack users. The `Vole` TUN
    /// runtime enables it explicitly.
    pub fake_icmp_echo: bool,
}

impl Default for NetStackConfig {
    fn default() -> Self {
        Self {
            mtu: 1_500,
            packet_queue: 64,
            tcp_accept_queue: 32,
            udp_queue: 128,
            tcp_recv_buffer: 32 * 1024,
            tcp_send_buffer: 32 * 1024,
            tcp_idle_timeout: Duration::from_mins(2),
            max_poll_interval: Duration::from_millis(100),
            fake_icmp_echo: false,
        }
    }
}

impl NetStackConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !(1_280..=65_535).contains(&self.mtu) {
            return Err(ConfigError::Mtu(self.mtu));
        }
        self.validate_resources()
    }

    pub(crate) fn validate_client(
        &self,
        client: &crate::client::ClientConfig,
    ) -> Result<(), ConfigError> {
        let minimum = if client.has_ipv6() { 1_280 } else { 68 };
        if !(minimum..=65_535).contains(&self.mtu) {
            return Err(ConfigError::ClientMtu {
                value: self.mtu,
                minimum,
            });
        }
        self.validate_resources()
    }

    fn validate_resources(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("packet_queue", self.packet_queue),
            ("tcp_accept_queue", self.tcp_accept_queue),
            ("udp_queue", self.udp_queue),
        ] {
            if value == 0 {
                return Err(ConfigError::ZeroLimit(name));
            }
        }
        for (name, value) in [
            ("tcp_recv_buffer", self.tcp_recv_buffer),
            ("tcp_send_buffer", self.tcp_send_buffer),
        ] {
            if value < 4 * 1024 || !value.is_multiple_of(2) {
                return Err(ConfigError::TcpBuffer { name, value });
            }
        }
        if self.tcp_idle_timeout.is_zero() {
            return Err(ConfigError::ZeroDuration("tcp_idle_timeout"));
        }
        if self.max_poll_interval.is_zero() {
            return Err(ConfigError::ZeroDuration("max_poll_interval"));
        }
        Ok(())
    }

    pub(crate) const fn recv_layer_buffer_size(&self) -> usize {
        self.tcp_recv_buffer / 2
    }

    pub(crate) const fn send_layer_buffer_size(&self) -> usize {
        self.tcp_send_buffer / 2
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("active netstack requires at least one configured source address")]
    NoClientAddress,
    #[error("active netstack {0} source address must be unicast")]
    ClientAddress(&'static str),
    #[error("active netstack source prefix is invalid")]
    ClientPrefix,
    #[error("active netstack source address is a subnet broadcast")]
    ClientBroadcast,
    #[error("active netstack MTU must be between {minimum} and 65535 bytes, got {value}")]
    ClientMtu { value: usize, minimum: usize },
    #[error("active netstack receive packet limit must be between 1 and 65575 bytes, got {0}")]
    ReceivePacketLimit(usize),
    #[error("MTU must be between 1280 and 65535 bytes, got {0}")]
    Mtu(usize),
    #[error("resource limit `{0}` must be greater than zero")]
    ZeroLimit(&'static str),
    #[error("duration `{0}` must be greater than zero")]
    ZeroDuration(&'static str),
    #[error("`{name}` must be even and at least 4096 bytes, got {value}")]
    TcpBuffer { name: &'static str, value: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_keep_queues_and_per_flow_buffers_bounded() {
        let config = NetStackConfig::default();
        assert_eq!(config.packet_queue, 64);
        assert_eq!(config.tcp_accept_queue, 32);
        assert_eq!(config.udp_queue, 128);
        assert_eq!(config.tcp_recv_buffer, 32 * 1024);
        assert_eq!(config.tcp_send_buffer, 32 * 1024);
        assert_eq!(config.recv_layer_buffer_size(), 16 * 1024);
        assert_eq!(config.send_layer_buffer_size(), 16 * 1024);
        config.validate().unwrap();
    }

    #[test]
    fn tcp_direction_buffers_are_validated_independently() {
        for value in [0, 4094, 4095, 4097] {
            let recv = NetStackConfig {
                tcp_recv_buffer: value,
                ..NetStackConfig::default()
            };
            assert_eq!(
                recv.validate(),
                Err(ConfigError::TcpBuffer {
                    name: "tcp_recv_buffer",
                    value,
                })
            );
            let send = NetStackConfig {
                tcp_send_buffer: value,
                ..NetStackConfig::default()
            };
            assert_eq!(
                send.validate(),
                Err(ConfigError::TcpBuffer {
                    name: "tcp_send_buffer",
                    value,
                })
            );
        }
        let config = NetStackConfig {
            tcp_recv_buffer: 4096,
            tcp_send_buffer: 8194,
            ..NetStackConfig::default()
        };
        config.validate().unwrap();
        assert_eq!(config.recv_layer_buffer_size(), 2048);
        assert_eq!(config.send_layer_buffer_size(), 4097);
    }

    #[test]
    fn rejects_zero_queue_capacity() {
        let config = NetStackConfig {
            udp_queue: 0,
            ..NetStackConfig::default()
        };
        assert_eq!(config.validate(), Err(ConfigError::ZeroLimit("udp_queue")));
    }
}
