//! Shared node wrapper options; protocol codecs remain independent.
use super::invalid;
use crate::Result;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SingMuxProtocol {
    #[default]
    #[serde(alias = "")]
    H2Mux,
    Smux,
    Yamux,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SingMuxConfig {
    pub enabled: bool,
    pub protocol: SingMuxProtocol,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
    pub only_tcp: bool,
    pub statistic: bool,
    pub brutal: Option<SingMuxBrutalConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingMuxBrutalConfig {
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawBrutal {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    up: Bandwidth,
    #[serde(default)]
    down: Bandwidth,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Bandwidth {
    Number(u64),
    Text(String),
}
impl Default for Bandwidth {
    fn default() -> Self {
        Self::Number(0)
    }
}
impl Bandwidth {
    fn bytes_per_second(self) -> Result<u64> {
        let text = match self {
            Self::Number(value) => value.to_string(),
            Self::Text(value) => value,
        };
        let text = text.trim();
        if text.is_empty() {
            return Ok(0);
        }
        let end = text.bytes().take_while(u8::is_ascii_digit).count();
        let Ok(value) = text[..end].parse::<u64>() else {
            return invalid("invalid sing-mux Brutal bandwidth");
        };
        let (factor, divisor) = match text[end..].trim() {
            "" | "Mbps" => (1_000_000_u64, 8),
            "bps" => (1, 8),
            "Kbps" => (1_000, 8),
            "Gbps" => (1_000_000_000, 8),
            "Tbps" => (1_000_000_000_000, 8),
            "Bps" => (1, 1),
            "KBps" => (1_000, 1),
            "MBps" => (1_000_000, 1),
            "GBps" => (1_000_000_000, 1),
            "TBps" => (1_000_000_000_000, 1),
            _ => return invalid("invalid sing-mux Brutal bandwidth unit"),
        };
        value
            .checked_mul(factor)
            .map(|rate| rate / divisor)
            .ok_or_else(|| {
                crate::VoleError::InvalidConfig("sing-mux Brutal bandwidth overflows".into())
            })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawSingMux {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    protocol: SingMuxProtocol,
    #[serde(default)]
    max_connections: isize,
    #[serde(default)]
    min_streams: isize,
    #[serde(default)]
    max_streams: isize,
    #[serde(default)]
    padding: bool,
    #[serde(default)]
    only_tcp: bool,
    #[serde(default)]
    statistic: bool,
    #[serde(default)]
    brutal_opts: RawBrutal,
}
impl RawSingMux {
    pub(super) fn normalize(self) -> Result<Option<SingMuxConfig>> {
        if !self.enabled {
            return Ok(None);
        }
        if !cfg!(feature = "sing-mux") {
            return invalid("sing-mux support is not enabled in this build");
        }
        // Apply the reference default to literal input, before collapsing
        // negative counts into disabled threshold conditions.
        let min_streams = if self.max_connections == 0 && self.max_streams == 0 {
            8
        } else {
            self.min_streams.max(0) as usize
        };
        Ok(Some(SingMuxConfig {
            enabled: true,
            protocol: self.protocol,
            max_connections: self.max_connections.max(0) as usize,
            min_streams,
            max_streams: self.max_streams.max(0) as usize,
            padding: self.padding,
            only_tcp: self.only_tcp,
            statistic: self.statistic,
            brutal: if self.brutal_opts.enabled {
                Some(SingMuxBrutalConfig {
                    up: self.brutal_opts.up.bytes_per_second()?,
                    down: self.brutal_opts.down.bytes_per_second()?,
                })
            } else {
                None
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sing-mux")]
    #[test]
    fn brutal_bandwidth_is_checked_and_uses_bytes_per_second() {
        for (up, down, expected) in [
            ("8", "\"125 KBps\"", (1_000_000, 125_000)),
            ("\"1Gbps\"", "\"2 MBps\"", (125_000_000, 2_000_000)),
            ("\"\"", "0", (0, 0)),
            ("\"18446744073709551615 Bps\"", "0", (u64::MAX, 0)),
        ] {
            let raw: RawSingMux = serde_yaml_ng::from_str(&format!(
                "enabled: true\nbrutal-opts: {{enabled: true, up: {up}, down: {down}}}"
            ))
            .unwrap();
            let brutal = raw.normalize().unwrap().unwrap().brutal.unwrap();
            assert_eq!((brutal.up, brutal.down), expected);
        }
        for bandwidth in [
            "\"18446744073709551615 Mbps\"",
            "\"18446744073709551616 Bps\"",
            "\"-1 Mbps\"",
            "\"1.5 Mbps\"",
            "\"1 MiBps\"",
        ] {
            let raw: RawSingMux = serde_yaml_ng::from_str(&format!(
                "enabled: true\nbrutal-opts: {{enabled: true, up: {bandwidth}}}"
            ))
            .unwrap();
            assert!(raw.normalize().is_err());
        }
    }

    #[cfg(feature = "sing-mux")]
    #[test]
    fn normalizes_literal_defaults_before_signed_thresholds() {
        for (yaml, expected) in [
            ("enabled: true\nmin-streams: 42", (0, 8, 0)),
            (
                "enabled: true\nmax-connections: -1\nmin-streams: -2",
                (0, 0, 0),
            ),
            (
                "enabled: true\nmax-connections: 2\nmin-streams: 3\nmax-streams: 4",
                (2, 3, 4),
            ),
        ] {
            let raw: RawSingMux = serde_yaml_ng::from_str(yaml).unwrap();
            let options = raw.normalize().unwrap().unwrap();
            assert_eq!(
                (
                    options.max_connections,
                    options.min_streams,
                    options.max_streams
                ),
                expected
            );
        }
    }

    #[cfg(not(feature = "sing-mux"))]
    #[test]
    fn disabled_build_rejects_enabled_wrapper_but_allows_disabled_options() {
        let enabled: RawSingMux = serde_yaml_ng::from_str("enabled: true").unwrap();
        assert!(
            enabled
                .normalize()
                .unwrap_err()
                .to_string()
                .contains("not enabled")
        );
        let disabled: RawSingMux =
            serde_yaml_ng::from_str("enabled: false\nprotocol: yamux").unwrap();
        assert!(disabled.normalize().unwrap().is_none());
    }
}
