//! Inline script declarations and pure compilation of their URL selectors.
use super::{
    config::{invalid, nonnull},
    rules::{MAX_PATTERN, MAX_RULE_TEXT, MAX_RULES, MatchKind, Phase, checked_url},
    scripts::{self, CompiledSource},
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use url::Url;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BodyMode {
    #[default]
    None,
    Text,
    Bytes,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawScripts {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default, deserialize_with = "nonnull")]
    scripts: Vec<RawScript>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawScript {
    name: String,
    #[serde(deserialize_with = "phase", serialize_with = "serialize_phase")]
    phase: Phase,
    url: String,
    #[serde(default, rename = "match")]
    match_kind: MatchKind,
    #[serde(default)]
    body: BodyMode,
    source: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum RawPhase {
    Request,
    Response,
}

fn phase<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Phase, D::Error> {
    RawPhase::deserialize(deserializer).map(|phase| match phase {
        RawPhase::Request => Phase::Request,
        RawPhase::Response => Phase::Response,
    })
}

fn serialize_phase<S: Serializer>(phase: &Phase, serializer: S) -> Result<S::Ok, S::Error> {
    match phase {
        Phase::Request => RawPhase::Request,
        Phase::Response => RawPhase::Response,
    }
    .serialize(serializer)
}

#[derive(Clone)]
enum Matcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

#[derive(Clone)]
pub(crate) struct CompiledScript {
    pub(crate) name: String,
    pub(crate) phase: Phase,
    pub(crate) body: BodyMode,
    pub(crate) compiled: CompiledSource,
    matcher: Matcher,
}

impl CompiledScript {
    pub(crate) fn matches(&self, url: &Url) -> bool {
        match &self.matcher {
            Matcher::Exact(value) => url.as_str() == value,
            Matcher::Prefix(value) => url.as_str().starts_with(value),
            Matcher::Regex(regex) => regex.is_match(url.as_str()),
        }
    }

    fn needs_jsc_for_business(&self) -> bool {
        self.compiled.needs_jsc_for_business(self.body, self.phase)
    }
}

impl RawScripts {
    pub(crate) fn is_active(&self) -> bool {
        self.enabled && !self.scripts.is_empty()
    }

    /// Platform admission belongs to actual preparation, never YAML validation.
    pub(crate) fn ensure_available(&self) -> io::Result<()> {
        if self.is_active() {
            scripts::ensure_available()?;
        }
        Ok(())
    }

    /// Initialize trusted platform state only from actual resource preparation.
    pub(crate) fn prepare_platform(
        &self,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> io::Result<()> {
        if self.is_active() {
            // Preparation still requires the supported platform even when a
            // closed Plan proves that business input cannot select JSC.
            scripts::ensure_available()?;
            if cancellation.is_cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            // Compile the whole immutable declaration list before deciding;
            // a total prefix must not hide an unchecked or JSC-only suffix.
            let needs_jsc = {
                let compiled = self.compile()?;
                compiled.iter().any(CompiledScript::needs_jsc_for_business)
            };
            if cancellation.is_cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if needs_jsc {
                scripts::prepare_platform(cancellation)?;
            }
        }
        Ok(())
    }

    /// Disabled declarations are validated too; enabling cannot expose a
    /// previously unchecked source or selector.
    pub(crate) fn compile(&self) -> io::Result<Vec<CompiledScript>> {
        if self.scripts.len() > MAX_RULES {
            return Err(invalid());
        }
        let mut text = 0usize;
        self.scripts
            .iter()
            .map(|script| {
                text = text
                    .checked_add(script.name.len())
                    .and_then(|size| size.checked_add(script.url.len()))
                    .filter(|size| *size <= MAX_RULE_TEXT)
                    .ok_or_else(invalid)?;
                if script.name.trim().is_empty()
                    || script.name.chars().any(char::is_control)
                    || script.url.len() > MAX_PATTERN
                {
                    return Err(invalid());
                }
                let matcher = match script.match_kind {
                    MatchKind::Exact => Matcher::Exact(checked_url(&script.url)?.to_string()),
                    MatchKind::Prefix => Matcher::Prefix(checked_url(&script.url)?.to_string()),
                    MatchKind::Regex => Matcher::Regex(
                        RegexBuilder::new(&script.url)
                            .size_limit(128 * 1024)
                            .dfa_size_limit(64 * 1024)
                            .build()
                            .map_err(|_| invalid())?,
                    ),
                };
                Ok(CompiledScript {
                    name: script.name.clone(),
                    phase: script.phase,
                    body: script.body,
                    compiled: scripts::validate_source(&script.source)?,
                    matcher,
                })
            })
            .collect()
    }
}

#[cfg(all(test, feature = "inbound-http"))]
mod tests {
    use super::*;

    const CLOSED: &str = "function rewrite(input){const text=input.body.data.replaceAll('a','b');return {type:'modify',body:{kind:'text',data:text}};}";
    const REQUEST_GUARD: &str = "function rewrite(input){let found=false;for(let i=0;i<input.request.headers.length;i++){if(input.request.headers[i].name==='x-required'){found=true;}}if(!found){return {type:'pass'};}return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b')}};}";
    const RESPONSE_GUARD: &str = "function rewrite(input){let found=false;for(let i=0;i<input.response.headers.length;i++){if(input.response.headers[i].name==='x-required'){found=true;}}if(!found){return {type:'pass'};}return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b')}};}";
    const UNUSED_UNKNOWN: &str = "function rewrite(input){const ignored=JSON.parse('null');return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b')}};}";

    fn declaration(source: &str, body: BodyMode, phase: Phase) -> RawScript {
        RawScript {
            name: "coverage-proof".into(),
            phase,
            url: "https://example.test/".into(),
            match_kind: MatchKind::Exact,
            body,
            source: source.into(),
        }
    }

    fn active(source: &str, body: BodyMode, phase: Phase) -> RawScripts {
        RawScripts {
            enabled: true,
            scripts: vec![declaration(source, body, phase)],
        }
    }

    #[test]
    fn jsc_preparation_proof_uses_the_actual_body_and_phase_declaration() {
        for phase in [Phase::Request, Phase::Response] {
            let compiled = active(CLOSED, BodyMode::Text, phase).compile().unwrap();
            assert_eq!(
                compiled[0].needs_jsc_for_business(),
                !cfg!(target_vendor = "apple")
            );
            for body in [BodyMode::None, BodyMode::Bytes] {
                let compiled = active(CLOSED, body, phase).compile().unwrap();
                assert!(compiled[0].needs_jsc_for_business());
            }
        }
    }

    #[test]
    fn guard_coverage_uses_the_actual_business_phase_and_body_declaration() {
        for (source, phase, covered) in [
            (REQUEST_GUARD, Phase::Request, true),
            (REQUEST_GUARD, Phase::Response, true),
            (RESPONSE_GUARD, Phase::Response, true),
            (RESPONSE_GUARD, Phase::Request, false),
        ] {
            let compiled = active(source, BodyMode::Text, phase).compile().unwrap();
            assert_eq!(
                compiled[0].needs_jsc_for_business(),
                !cfg!(target_vendor = "apple") || !covered
            );
            for body in [BodyMode::None, BodyMode::Bytes] {
                let compiled = active(source, body, phase).compile().unwrap();
                assert!(compiled[0].needs_jsc_for_business());
            }
        }
    }

    #[test]
    fn unused_unknown_ast_keeps_eager_jsc_preparation() {
        for phase in [Phase::Request, Phase::Response] {
            // A valid original-frontend program cannot prove coverage by
            // ignoring an unused statement outside the closed Plan subset.
            let compiled = active(UNUSED_UNKNOWN, BodyMode::Text, phase)
                .compile()
                .unwrap();
            assert!(compiled[0].needs_jsc_for_business());
        }
    }

    #[test]
    fn omitted_body_declaration_keeps_eager_jsc_preparation() {
        let raw: RawScripts = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "scripts": [{
                "name": "default-body",
                "phase": "response",
                "url": "https://example.test/",
                "match": "exact",
                "source": CLOSED,
            }],
        }))
        .unwrap();
        let compiled = raw.compile().unwrap();
        assert_eq!(compiled[0].body, BodyMode::None);
        assert!(compiled[0].needs_jsc_for_business());
    }

    #[test]
    fn disabled_sources_still_receive_the_complete_frontend_validation() {
        let mut valid = active(UNUSED_UNKNOWN, BodyMode::Text, Phase::Response);
        valid.enabled = false;
        assert!(valid.compile().is_ok());
        valid.scripts[0].source = "function rewrite(input){return async () => 1;}".into();
        assert!(valid.compile().is_err());
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn only_a_complete_total_list_skips_the_platform_prepare_request() {
        use tokio_util::sync::CancellationToken;

        let requested = scripts::platform_prepare_requests_for_test();
        let mut total = active(CLOSED, BodyMode::Text, Phase::Response);
        total.scripts.extend([
            declaration(CLOSED, BodyMode::Text, Phase::Request),
            declaration(REQUEST_GUARD, BodyMode::Text, Phase::Request),
            declaration(REQUEST_GUARD, BodyMode::Text, Phase::Response),
            declaration(RESPONSE_GUARD, BodyMode::Text, Phase::Response),
        ]);
        total.compile().unwrap();
        total.ensure_available().unwrap();
        assert_eq!(scripts::platform_prepare_requests_for_test(), requested);
        total.prepare_platform(&CancellationToken::new()).unwrap();
        assert_eq!(scripts::platform_prepare_requests_for_test(), requested);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            total.prepare_platform(&cancelled).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(scripts::platform_prepare_requests_for_test(), requested);

        let mut disabled = active(RESPONSE_GUARD, BodyMode::Text, Phase::Request);
        disabled.enabled = false;
        disabled
            .prepare_platform(&CancellationToken::new())
            .unwrap();
        RawScripts {
            enabled: true,
            scripts: Vec::new(),
        }
        .prepare_platform(&CancellationToken::new())
        .unwrap();
        assert_eq!(scripts::platform_prepare_requests_for_test(), requested);

        let mut mixed = total;
        mixed
            .scripts
            .push(declaration(RESPONSE_GUARD, BodyMode::Text, Phase::Request));
        mixed.prepare_platform(&CancellationToken::new()).unwrap();
        assert_eq!(scripts::platform_prepare_requests_for_test(), requested + 1);
        // A second actual preparation requests the existing process-global
        // initializer again; its own shared success/retry policy is unchanged.
        mixed.prepare_platform(&CancellationToken::new()).unwrap();
        assert_eq!(scripts::platform_prepare_requests_for_test(), requested + 2);
    }

    #[cfg(not(target_vendor = "apple"))]
    #[test]
    fn total_source_does_not_expand_platform_availability() {
        let total = active(CLOSED, BodyMode::Text, Phase::Request);
        assert_eq!(
            total
                .prepare_platform(&tokio_util::sync::CancellationToken::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
