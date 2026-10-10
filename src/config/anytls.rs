use std::time::Duration;

use super::invalid;
use crate::Result;

#[derive(Clone, PartialEq, Eq)]
pub struct AnyTlsSessionOptions {
    pub check_interval: Duration,
    pub idle_timeout: Duration,
    pub min_idle: usize,
    pub disable_reuse: bool,
    pub client_metadata: String,
}

impl Default for AnyTlsSessionOptions {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            min_idle: 0,
            disable_reuse: false,
            client_metadata: String::new(),
        }
    }
}

impl std::fmt::Debug for AnyTlsSessionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsSessionOptions")
            .field("check_interval", &self.check_interval)
            .field("idle_timeout", &self.idle_timeout)
            .field("min_idle", &self.min_idle)
            .field("disable_reuse", &self.disable_reuse)
            .finish_non_exhaustive()
    }
}

impl AnyTlsSessionOptions {
    pub(super) fn normalize(
        interval: i64,
        timeout: i64,
        minimum: i64,
        disable_reuse: bool,
        client_metadata: String,
    ) -> Result<Self> {
        // Settings are a newline-delimited map. An embedded delimiter would
        // turn metadata into other settings instead of a single client value.
        if client_metadata.len() > usize::from(u16::MAX) - 80 || client_metadata.contains('\n') {
            return invalid("AnyTLS client-metadata exceeds the Settings value boundary");
        }
        fn seconds(value: i64) -> Result<Duration> {
            let duration = Duration::from_secs(if value <= 5 { 30 } else { value as u64 });
            if std::time::Instant::now().checked_add(duration).is_none() {
                return invalid("AnyTLS session interval exceeds the clock range");
            }
            Ok(duration)
        }
        Ok(Self {
            check_interval: seconds(interval)?,
            idle_timeout: seconds(timeout)?,
            min_idle: usize::try_from(minimum.max(0)).map_err(|_| {
                crate::VoleError::InvalidConfig(
                    "AnyTLS min-idle-session exceeds the platform range".into(),
                )
            })?,
            disable_reuse,
            client_metadata,
        })
    }
}
