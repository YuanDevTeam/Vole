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
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
