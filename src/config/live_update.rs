//! Startup resources are owned by the host; a live candidate only replaces graphs.
use super::{Config, providers::ProviderTemplate};
use crate::{Result, VoleError, resource::config_apply::ConfigPatch};
use serde_yaml_ng::{Mapping, Value};
use std::{path::Path, sync::Arc};

impl ProviderTemplate {
    pub(crate) fn update_yaml(bytes: &[u8], directory: &Path) -> Result<Arc<Self>> {
        let mut template = Self::extract(super::yaml::parse(bytes)?)?;
        template.identity_directory = Some(directory.to_owned());
        Ok(Arc::new(template))
    }
    pub(crate) fn patched(&self, patch: &ConfigPatch) -> Result<Arc<Self>> {
        let mut next = self.clone();
        let base = next
            .base
            .as_mapping_mut()
            .ok_or_else(|| VoleError::InvalidConfig("invalid configuration candidate".into()))?;
        for (key, value) in [
            ("mode", patch.mode.as_deref()),
            ("log-level", patch.log_level.as_deref()),
            ("find-process-mode", patch.find_process_mode.as_deref()),
            ("interface-name", patch.interface_name.as_deref()),
        ] {
            if let Some(value) = value {
                base.insert(key.into(), Value::String(value.into()));
            }
        }
        if let Some(value) = patch.tcp_concurrent {
            base.insert("tcp-concurrent".into(), Value::Bool(value));
        }
        if let Some(value) = patch.sniffing {
            let sniffer = base
                .entry(Value::String("sniffer".into()))
                .or_insert_with(|| Value::Mapping(Mapping::new()))
                .as_mapping_mut()
                .ok_or_else(|| {
                    VoleError::InvalidConfig("invalid configuration candidate".into())
                })?;
            sniffer.insert("enable".into(), Value::Bool(value));
        }
        Ok(Arc::new(next))
    }
}

pub(crate) fn startup_compatible(current: &Config, next: &Config) -> bool {
    current.tls == next.tls
        && current.ipv6 == next.ipv6
        && current.external_controller == next.external_controller
        && current.inbounds == next.inbounds
        && current.mixed_port == next.mixed_port
        && current.tun == next.tun
        && current.profile == next.profile
        && current.geodata_update == next.geodata_update
        && current.dns.fake_ip.enabled == next.dns.fake_ip.enabled
        && current.dns.fake_ip.range == next.dns.fake_ip.range
        && current.dns.fake_ip.range6 == next.dns.fake_ip.range6
        && (!current.dns.fake_ip.enabled || current.dns.ipv6 == next.dns.ipv6)
        && (!(current.tun.enable && current.tun.file_descriptor == 0 && current.tun.auto_route)
            || current.egress == next.egress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FindProcessMode, Mode, providers::ProviderContents};
    #[test]
    fn patch_keeps_provider_identity_and_maps_the_actual_api_sniffing_field() {
        let config=Config::parse_yaml(b"sniffer: {enable: true, sniff: {TLS: {ports: [443]}}}\nproxy-providers: {fixture: {type: inline, payload: [{name: edge, type: direct}]}}\nproxy-groups: [{name: chosen, type: select, use: [fixture]}]\nrules: ['MATCH,chosen']\n").unwrap();
        let template = config.providers.unwrap();
        let next = template
            .patched(&ConfigPatch {
                mode: Some("direct".into()),
                log_level: Some("warning".into()),
                sniffing: Some(false),
                tcp_concurrent: Some(true),
                find_process_mode: Some("off".into()),
                interface_name: Some("eth0".into()),
            })
            .unwrap();
        assert_eq!(next.proxies, template.proxies);
        assert!(next.base.get("sniffing").is_none());
        let next = next.materialize(&ProviderContents::new()).unwrap();
        assert_eq!(next.mode, Mode::Direct);
        assert!(!next.sniffer.enable);
        assert!(next.connections.tcp_concurrent);
        assert_eq!(next.find_process_mode, FindProcessMode::Off);
    }
    #[test]
    fn live_candidates_reject_startup_resource_changes_but_allow_new_routes() {
        let config = Config::parse_yaml(b"ipv6: false\nrules: ['MATCH,DIRECT']\n").unwrap();
        for yaml in [
            b"ipv6: true\nrules: ['MATCH,DIRECT']\n".as_slice(),
            b"ipv6: false\nmixed-port: 1080\nrules: ['MATCH,DIRECT']\n",
            b"ipv6: false\nexternal-controller: 127.0.0.1:9090\nrules: ['MATCH,DIRECT']\n",
            b"ipv6: false\ndns: {enhanced-mode: fake-ip}\nrules: ['MATCH,DIRECT']\n",
        ] {
            let next = Config::parse_yaml(yaml).unwrap();
            assert!(!startup_compatible(&config, &next));
        }
        let next = Config::parse_yaml(b"ipv6: false\nrules: ['MATCH,REJECT']\nlog-level: debug\n")
            .unwrap();
        assert!(startup_compatible(&config, &next));
    }
}
