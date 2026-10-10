use std::sync::Arc;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerCors {
    #[serde(rename = "allow-origins", default)]
    pub allow_origins: Vec<String>,
    #[serde(rename = "allow-private-network", default = "private_network_default")]
    pub allow_private_network: bool,
}

fn private_network_default() -> bool {
    true
}

impl Default for ControllerCors {
    fn default() -> Self {
        Self {
            allow_origins: Vec::new(),
            allow_private_network: true,
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerTls {
    #[serde(default)]
    pub certificate: Arc<str>,
    #[serde(rename = "private-key", default)]
    pub private_key: Arc<str>,
    #[serde(rename = "client-auth-type", default)]
    pub client_auth_type: Arc<str>,
    #[serde(rename = "client-auth-cert", default)]
    pub client_auth_cert: Arc<str>,
}

impl std::fmt::Debug for ControllerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerTls").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn controller_secure_configuration_keeps_http_tls_and_client_trust_separate() {
        let config = super::super::Config::parse_yaml(
            b"external-controller: 127.0.0.1:0\nexternal-controller-tls: 127.0.0.1:0\nsecret: token\nexternal-controller-cors:\n  allow-origins: ['https://*.example']\n  allow-private-network: true\ntls:\n  certificate: certificate-material\n  private-key: secret-private-material\n  client-auth-type: unknown-mode\n",
        )
        .unwrap();
        assert!(config.tls.certificates.is_empty());
        let controller = config.external_controller.unwrap();
        assert!(controller.http_enabled);
        assert!(controller.tls_listen.is_some());
        assert!(controller.cors.allow_private_network);
        assert_eq!(controller.cors.allow_origins, ["https://*.example"]);
        assert_eq!(&*controller.server_tls.client_auth_type, "unknown-mode");
        assert!(!format!("{:?}", controller.server_tls).contains("secret-private-material"));
        let tls_only = super::super::Config::parse_yaml(b"external-controller-tls: 127.0.0.1:0\n")
            .unwrap()
            .external_controller
            .unwrap();
        assert!(!tls_only.http_enabled);
        assert!(tls_only.tls_listen.is_some());
        assert!(tls_only.cors.allow_private_network);
        let explicit: super::ControllerCors =
            serde_yaml_ng::from_str("allow-private-network: false").unwrap();
        assert!(!explicit.allow_private_network);
        let omitted: super::ControllerCors = serde_yaml_ng::from_str("{}").unwrap();
        assert!(omitted.allow_private_network);
    }
}
