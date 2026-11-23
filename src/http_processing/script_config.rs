//! Compiled inline script declarations share the native rule's selector.
use super::{
    config::ParameterValue,
    rules::{Phase, RequestMatch, RequestSelector, same_origin},
    scripts::CompiledSource,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use url::Url;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BodyMode {
    #[default]
    None,
    Text,
    Bytes,
}

#[derive(Clone)]
pub(crate) struct CompiledScript {
    pub(crate) name: String,
    #[cfg(feature = "invoke")]
    pub(crate) location: super::config::SourceLocation,
    pub(crate) phase: Phase,
    pub(crate) body: BodyMode,
    pub(crate) compiled: CompiledSource,
    pub(super) selector: Arc<RequestSelector>,
    pub(crate) parameters: Arc<BTreeMap<String, ParameterValue>>,
    pub(super) parameter_bytes: usize,
    pub(super) managed: bool,
}

impl CompiledScript {
    pub(crate) fn matches<'a>(&self, original: impl Into<RequestMatch<'a>>) -> bool {
        self.selector.matches(original.into())
    }

    pub(super) fn needs_jsc_for_business(&self) -> bool {
        self.compiled.needs_jsc_for_business(self.body, self.phase)
    }

    pub(crate) fn allows_upstream(&self, previous: &Url, candidate: &Url) -> bool {
        !self.managed || same_origin(previous, candidate)
    }

    pub(crate) fn parameter_work_bytes(&self) -> usize {
        self.parameter_bytes
    }
}

#[cfg(all(test, feature = "inbound-http"))]
mod tests {
    use super::*;
    use crate::http_processing::config::{Document, PolicyCandidate};
    use std::io;

    const CLOSED: &str = "function rewrite(input){const text=input.body.data.replaceAll('a','b');return {type:'modify',body:{kind:'text',data:text}};}";
    const RESPONSE_GUARD: &str = "function rewrite(input){let found=false;for(let i=0;i<input.response.headers.length;i++){if(input.response.headers[i].name==='x-required'){found=true;}}if(!found){return {type:'pass'};}return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b')}};}";

    fn candidate(
        origin: &str,
        declarations: &[(&str, BodyMode, Phase)],
    ) -> io::Result<Arc<PolicyCandidate>> {
        let rules: Vec<_> = declarations
            .iter()
            .map(|(source, body, phase)| {
                let script = serde_json::json!({"js": {"body":body, "source":source}});
                match phase {
                    Phase::Request => serde_json::json!({"request":script}),
                    Phase::Response => serde_json::json!({"response":script}),
                }
            })
            .collect();
        Document::parse(
            &serde_json::json!({"targets": [{"origins":[origin], "rules":rules}]}).to_string(),
        )?
        .compile()
    }

    #[test]
    fn platform_proof_uses_the_actual_body_and_phase_declaration() {
        let candidate = candidate(
            "http://example.test",
            &[
                (CLOSED, BodyMode::Text, Phase::Request),
                (CLOSED, BodyMode::Bytes, Phase::Request),
                (RESPONSE_GUARD, BodyMode::Text, Phase::Response),
                (RESPONSE_GUARD, BodyMode::Text, Phase::Request),
            ],
        )
        .unwrap();
        assert_eq!(
            candidate
                .scripts
                .iter()
                .map(CompiledScript::needs_jsc_for_business)
                .collect::<Vec<_>>(),
            [
                !cfg!(target_vendor = "apple"),
                true,
                !cfg!(target_vendor = "apple"),
                true
            ]
        );
    }

    #[test]
    fn disabled_https_scripts_still_receive_frontend_validation() {
        assert!(
            candidate(
                "https://example.test",
                &[(
                    "function rewrite(input){return async () => 1;}",
                    BodyMode::None,
                    Phase::Request
                )],
            )
            .is_err()
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn only_active_scripts_can_initialize_the_platform() {
        use crate::http_processing::config::HttpSettings;
        use tokio_util::sync::CancellationToken;

        let count = super::super::scripts::platform_prepare_requests_for_test;
        let requested = count();
        let cancellation = CancellationToken::new();
        let default = HttpSettings::default();
        let closed = (CLOSED, BodyMode::Text, Phase::Request);
        let response_guard = (RESPONSE_GUARD, BodyMode::Text, Phase::Request);

        candidate("http://example.test", &[closed])
            .unwrap()
            .prepare_platform(&default, &cancellation)
            .unwrap();
        candidate("https://example.test", &[response_guard])
            .unwrap()
            .prepare_platform(&default, &cancellation)
            .unwrap();
        let active = candidate("http://example.test", &[closed, response_guard]).unwrap();
        active
            .prepare_platform(
                &HttpSettings {
                    js_enabled: false,
                    ..default.clone()
                },
                &cancellation,
            )
            .unwrap();
        assert_eq!(count(), requested);
        active.prepare_platform(&default, &cancellation).unwrap();
        assert_eq!(count(), requested + 1);
    }

    #[cfg(not(any(
        target_vendor = "apple",
        all(
            feature = "http-js-quickjs",
            any(target_os = "android", target_os = "linux", windows)
        )
    )))]
    #[test]
    fn total_source_does_not_expand_platform_availability() {
        use crate::http_processing::config::HttpSettings;
        use tokio_util::sync::CancellationToken;

        let active = candidate(
            "http://example.test",
            &[(CLOSED, BodyMode::Text, Phase::Request)],
        )
        .unwrap();
        assert_eq!(
            active
                .prepare_platform(&HttpSettings::default(), &CancellationToken::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
