//! Concrete foreground overrides; immutable YAML and native Invoke are unchanged.
use super::{InvokeFailure, failure, input};
use crate::config::{Config, ExternalControllerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Default)]
pub(in crate::invoke) struct ControllerOverrides {
    http: Option<SocketAddr>,
    tls: Option<SocketAddr>,
    secret: Option<Zeroizing<String>>,
}
impl ControllerOverrides {
    pub(in crate::invoke) fn read(
        http: Option<Zeroizing<String>>,
        tls: Option<Zeroizing<String>>,
        secret: Option<Zeroizing<String>>,
    ) -> Result<Self, InvokeFailure> {
        let limit = crate::config::MAX_CONFIG_BYTES;
        Self::from_values(
            input::option_text(http, "VOLE_OVERRIDE_EXTERNAL_CONTROLLER", limit)?,
            input::option_text(tls, "VOLE_OVERRIDE_EXTERNAL_CONTROLLER_TLS", limit)?,
            input::option_text(secret, "VOLE_OVERRIDE_SECRET", limit)?,
        )
    }
    fn from_values(
        http: Option<Zeroizing<String>>,
        tls: Option<Zeroizing<String>>,
        secret: Option<Zeroizing<String>>,
    ) -> Result<Self, InvokeFailure> {
        fn listener(value: Option<Zeroizing<String>>) -> Result<Option<SocketAddr>, InvokeFailure> {
            crate::config::normalize_external_controller(
                value.map(|mut value| std::mem::take(&mut *value)),
                None,
            )
            .map(|value| value.map(|value| value.listen))
            .map_err(|_| failure("invalid foreground Controller address"))
        }
        Ok(Self {
            http: listener(http)?,
            tls: listener(tls)?,
            secret: secret.filter(|value| !value.is_empty()),
        })
    }
    pub(in crate::invoke) fn apply_template(
        &self,
        template: &mut crate::config::providers::ProviderTemplate,
    ) {
        template.override_controller(
            self.http,
            self.tls,
            self.secret.as_ref().map(|value| value.as_str()),
        );
    }
    pub(in crate::invoke) fn apply(&self, config: &mut Config) {
        if let Some(template) = &mut config.providers {
            self.apply_template(Arc::make_mut(template));
        }
        if (self.http.is_some() || self.tls.is_some()) && config.external_controller.is_none() {
            config.external_controller = Some(ExternalControllerConfig {
                http_enabled: false,
                secret: config
                    .providers
                    .as_ref()
                    .and_then(|template| template.controller_secret().map(str::to_owned)),
                cors: config
                    .providers
                    .as_ref()
                    .map_or_else(Default::default, |template| template.controller_cors()),
                server_tls: config.tls.server.clone(),
                ..ExternalControllerConfig::default()
            });
        }
        let Some(controller) = &mut config.external_controller else {
            return;
        };
        if let Some(http) = self.http {
            controller.listen = http;
            controller.http_enabled = true;
        }
        if let Some(tls) = self.tls {
            if !controller.http_enabled {
                controller.listen = tls;
            }
            controller.tls_listen = Some(tls);
        }
        if let Some(secret) = &self.secret {
            if let Some(mut old) = controller.secret.take() {
                old.zeroize();
            }
            controller.secret = Some(secret.as_str().to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(value: &str) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(value.to_owned()))
    }
    #[test]
    fn activating_controller_preserves_validated_secret_cors_and_tls_across_materialization() {
        let mut config = Config::parse_yaml(
            br#"
secret: yaml-token
external-controller-cors: {allow-origins: ['https://ui.example'], allow-private-network: false}
tls: {certificate: cert-material, private-key: key-material, client-auth-type: require-any}
rules: ['MATCH,DIRECT']
"#,
        )
        .unwrap();
        assert!(config.external_controller.is_none());
        let tls = config.tls.server.clone();
        ControllerOverrides::from_values(text("localhost:9000"), None, text(""))
            .unwrap()
            .apply(&mut config);
        let controller = config.external_controller.as_ref().unwrap();
        assert_eq!(controller.secret.as_deref(), Some("yaml-token"));
        assert_eq!(controller.cors.allow_origins, ["https://ui.example"]);
        assert!(!controller.cors.allow_private_network);
        assert_eq!(controller.server_tls, tls);
        let materialized = config
            .providers
            .as_ref()
            .unwrap()
            .materialize(&Default::default())
            .unwrap();
        assert_eq!(materialized.external_controller, config.external_controller);
        ControllerOverrides::from_values(None, None, text("explicit-token"))
            .unwrap()
            .apply(&mut config);
        let materialized = config
            .providers
            .as_ref()
            .unwrap()
            .materialize(&Default::default())
            .unwrap();
        assert_eq!(
            config
                .external_controller
                .as_ref()
                .unwrap()
                .secret
                .as_deref(),
            Some("explicit-token")
        );
        assert_eq!(materialized.external_controller, config.external_controller);
    }

    #[test]
    fn concrete_overrides_preserve_yaml_and_only_replace_nonempty_values() {
        let mut config = Config::parse_yaml(b"external-controller: localhost:9000\nexternal-controller-tls: ':9443'\nsecret: yaml-token\n").unwrap();
        ControllerOverrides::from_values(text(""), text(""), text(""))
            .unwrap()
            .apply(&mut config);
        let controller = config.external_controller.as_ref().unwrap();
        assert_eq!(controller.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(controller.tls_listen, Some("[::]:9443".parse().unwrap()));
        assert_eq!(controller.secret.as_deref(), Some("yaml-token"));
        ControllerOverrides::from_values(text("[::1]:9100"), None, text("runtime-token"))
            .unwrap()
            .apply(&mut config);
        let controller = config.external_controller.as_ref().unwrap();
        assert_eq!(controller.listen, "[::1]:9100".parse().unwrap());
        assert_eq!(controller.tls_listen, Some("[::]:9443".parse().unwrap()));
        assert_eq!(controller.secret.as_deref(), Some("runtime-token"));
        let mut absent = Config::parse_yaml(b"rules: ['MATCH,DIRECT']").unwrap();
        ControllerOverrides::from_values(None, None, text("unused-token"))
            .unwrap()
            .apply(&mut absent);
        assert!(absent.external_controller.is_none());
        ControllerOverrides::from_values(None, text("localhost:9443"), text("tls-token"))
            .unwrap()
            .apply(&mut absent);
        let controller = absent.external_controller.unwrap();
        assert!(!controller.http_enabled);
        assert_eq!(
            controller.tls_listen,
            Some("127.0.0.1:9443".parse().unwrap())
        );
        assert_eq!(controller.secret.as_deref(), Some("tls-token"));
    }
    #[test]
    fn concrete_overrides_survive_provider_materialization_and_content_updates() {
        use crate::config::providers::{ProviderContent, ProviderContents};
        let mut config = Config::parse_yaml(b"proxy-providers: {nodes: {type: inline, payload: [{name: edge, type: direct}]}}\nproxy-groups: [{name: choice, type: select, use: [nodes]}]\nrules: ['MATCH,choice']\n").unwrap();
        ControllerOverrides::from_values(
            text("localhost:9000"),
            text("[::1]:9443"),
            text("private-token"),
        )
        .unwrap()
        .apply(&mut config);
        let expected = config.external_controller.clone();
        let template = config.providers.unwrap();
        let materialized = template.materialize(&ProviderContents::new()).unwrap();
        assert_eq!(materialized.external_controller, expected);
        let mut contents = ProviderContents::new();
        contents.insert(
            "proxies/nodes".into(),
            ProviderContent::Proxies(vec![
                serde_yaml_ng::from_str("{name: next, type: direct}").unwrap(),
            ]),
        );
        let updated = template.materialize(&contents).unwrap();
        assert_eq!(updated.external_controller, expected);
        assert!(updated.proxies.iter().any(|node| node.tag == "next"));
    }
    #[test]
    fn concrete_override_addresses_reuse_the_existing_controller_parser() {
        assert!(
            ControllerOverrides::from_values(text("private-fixture.invalid:80"), None, None)
                .is_err()
        );
        assert!(ControllerOverrides::from_values(None, text("127.0.0.1:65536"), None).is_err());
    }
}
