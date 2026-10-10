//! Shared Mihomo gRPC options for stream protocols.
use super::{deserialize_present_option, invalid};
use crate::Result;
use serde::Deserialize;

#[derive(Clone, PartialEq, Eq)]
pub struct GrpcOptions {
    pub user_agent: String,
    pub ping_interval: u64,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}
impl std::fmt::Debug for GrpcOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcOptions").finish_non_exhaustive()
    }
}
impl Default for GrpcOptions {
    fn default() -> Self {
        Self {
            user_agent: "grpc-go/1.36.0".into(),
            ping_interval: 0,
            max_connections: 1,
            min_streams: 0,
            max_streams: 0,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawGrpc {
    #[serde(rename = "grpc-service-name", default)]
    service: String,
    #[serde(
        rename = "grpc-user-agent",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    user_agent: Option<String>,
    #[serde(rename = "ping-interval", default)]
    ping_interval: isize,
    #[serde(rename = "max-connections", default)]
    max_connections: isize,
    #[serde(rename = "min-streams", default)]
    min_streams: isize,
    #[serde(rename = "max-streams", default)]
    max_streams: isize,
}

impl RawGrpc {
    pub(super) fn normalize(self) -> Result<(String, GrpcOptions)> {
        if self.ping_interval < 0 {
            return invalid("negative gRPC ping-interval is unsupported");
        }
        let service = if self.service.is_empty() {
            "GunService".into()
        } else {
            self.service
        };
        let path = if service.starts_with('/') {
            service
        } else {
            format!("/{service}/Tun")
        };
        if path.contains(['?', '\r', '\n', '#']) {
            return invalid("invalid gRPC service path");
        }
        let user_agent = self
            .user_agent
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "grpc-go/1.36.0".into());
        let ping_interval = self.ping_interval as u64;
        if user_agent.len() > 8192
            || user_agent.parse::<http::HeaderValue>().is_err()
            || std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(ping_interval))
                .is_none()
        {
            return invalid("invalid gRPC options");
        }
        let positive = |value: isize| value.max(0) as usize;
        // Match the literal all-zero default before collapsing negative values:
        // negative thresholds disable a branch rather than opting into defaults.
        let max_connections =
            if self.max_connections == 0 && self.min_streams == 0 && self.max_streams == 0 {
                1
            } else {
                positive(self.max_connections)
            };
        Ok((
            path,
            GrpcOptions {
                user_agent,
                ping_interval,
                max_connections,
                min_streams: positive(self.min_streams),
                max_streams: positive(self.max_streams),
            },
        ))
    }
}
