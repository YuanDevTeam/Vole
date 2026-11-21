//! Local HTTP policy binding shared by foreground and native Invoke adapters.
use super::InvokeFailure;
use crate::{
    config::Config,
    http_processing::{
        Policy,
        config::{Document, HttpSettings, ParameterValue, PluginInput, PolicyCandidate},
        private_context::CaMaterial,
    },
};
use serde::{Deserialize, Deserializer, de};
use std::{collections::BTreeMap, io, sync::Arc};
use tokio_util::sync::CancellationToken;
#[path = "http_test.rs"]
mod evaluation;
pub(super) use evaluation::{TestPayload, TestResources, evaluate};

pub(super) fn check_envelope(input: &str) -> Result<Option<TestResources>, InvokeFailure> {
    use serde_json::value::RawValue;
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow)]
        method: &'a RawValue,
        #[serde(borrow)]
        payload: &'a RawValue,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Input<'a> {
        #[serde(borrow)]
        config_yaml: Option<&'a RawValue>,
        #[serde(default, borrow, deserialize_with = "present")]
        http_config_yaml: Option<&'a RawValue>,
        #[serde(default, borrow, deserialize_with = "present")]
        http_config_yamls: Option<&'a RawValue>,
        #[serde(default, borrow, deserialize_with = "present")]
        http_plugins: Option<&'a RawValue>,
        #[serde(borrow)]
        http_context: Option<&'a RawValue>,
        #[serde(borrow)]
        request: Option<&'a RawValue>,
        #[serde(borrow)]
        response: Option<&'a RawValue>,
        #[serde(borrow)]
        url: Option<&'a RawValue>,
        execute_scripts: Option<bool>,
    }
    #[derive(Deserialize)]
    struct Context<'a> {
        #[serde(borrow)]
        ca: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Ca<'a> {
        #[serde(borrow)]
        certificate: &'a RawValue,
        #[serde(borrow)]
        private_key: &'a RawValue,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Sample<'a> {
        #[serde(borrow)]
        body_base64: Option<&'a RawValue>,
        #[serde(borrow)]
        headers: Option<&'a RawValue>,
        #[serde(borrow)]
        method: Option<&'a RawValue>,
        #[serde(borrow)]
        status: Option<&'a RawValue>,
    }
    let invalid = |_| InvokeFailure::invalid_request("invalid HTTP input envelope");
    let envelope: Envelope<'_> = serde_json::from_str(input).map_err(invalid)?;
    if envelope.method.get().len() > 256 {
        return Err(InvokeFailure::invalid_request("invalid method"));
    }
    let method: String = serde_json::from_str(envelope.method.get()).map_err(invalid)?;
    if !matches!(
        method.as_str(),
        "start" | "reconnect" | "validateConfig" | "testHttp"
    ) {
        return Ok(None);
    }
    if input.len().saturating_sub(envelope.payload.get().len()) > 64 * 1024 {
        return Err(InvokeFailure::invalid_request(
            "HTTP envelope overhead exceeds limit",
        ));
    }
    let input: Input<'_> = serde_json::from_str(envelope.payload.get()).map_err(invalid)?;
    if input.execute_scripts.is_some() && method != "testHttp" {
        return Err(InvokeFailure::invalid_request(
            "executeScripts requires testHttp",
        ));
    }
    let known: usize = [
        input.config_yaml,
        input.http_config_yaml,
        input.http_config_yamls,
        input.http_plugins,
        input.http_context,
        input.request,
        input.response,
        input.url,
    ]
    .into_iter()
    .flatten()
    .map(|raw| raw.get().len())
    .sum();
    if envelope.payload.get().len().saturating_sub(known) > 64 * 1024 {
        return Err(InvokeFailure::invalid_request(
            "HTTP payload overhead exceeds limit",
        ));
    }
    if let Some(raw) = input.url {
        super::check_json_string_limit(raw.get(), crate::http_processing::rules::MAX_URL)?;
    }
    if let Some(raw) = input.config_yaml {
        super::check_json_string_limit(raw.get(), crate::config::MAX_CONFIG_BYTES)?;
    }
    check_document_values(input.http_config_yaml, input.http_config_yamls)?;
    if let Some(plugins) = input.http_plugins {
        if input.http_config_yaml.is_some() || input.http_config_yamls.is_some() {
            return Err(plugin_conflict());
        }
        check_managed_values(plugins)?;
    }
    if let Some(raw) = input.http_context {
        if raw.get().len()
            > super::MAX_ERROR_BYTES
                + super::MAX_ERROR_BYTES
                + crate::http_processing::private_context::MAX_CA_INPUT
        {
            return Err(InvokeFailure::invalid_request(
                "HTTP context exceeds input limit",
            ));
        }
        let context: Context<'_> = serde_json::from_str(raw.get()).map_err(invalid)?;
        if let Some(raw) = context.ca {
            if !matches!(method.as_str(), "start" | "reconnect") {
                return Err(InvokeFailure::invalid_request(
                    "this operation does not accept CA material",
                ));
            }
            let ca: Ca<'_> = serde_json::from_str(raw.get()).map_err(invalid)?;
            for raw in [ca.certificate, ca.private_key] {
                super::check_json_string_limit(
                    raw.get(),
                    crate::http_processing::private_context::MAX_CA_PEM_BYTES,
                )?;
            }
        }
    }
    for raw in [input.request, input.response].into_iter().flatten() {
        let sample: Sample<'_> = serde_json::from_str(raw.get()).map_err(invalid)?;
        let known: usize = [
            sample.body_base64,
            sample.headers,
            sample.method,
            sample.status,
        ]
        .into_iter()
        .flatten()
        .map(|raw| raw.get().len())
        .sum();
        if raw.get().len().saturating_sub(known) > 4096
            || sample.status.is_some_and(|raw| raw.get().len() > 8)
        {
            return Err(InvokeFailure::invalid_request(
                "HTTP sample overhead exceeds limit",
            ));
        }
        if let Some(raw) = sample.method {
            super::check_json_string_limit(raw.get(), 64)?;
        }
        if let Some(raw) = sample.body_base64 {
            super::check_json_string_limit(
                raw.get(),
                crate::http_processing::body::MAX_BODY.div_ceil(3) * 4,
            )?;
        }
        if sample.headers.is_some_and(|headers| {
            headers.get().len() > 6 * crate::http_processing::headers::MAX_BYTES + 4096
        }) {
            return Err(InvokeFailure::invalid_request(
                "HTTP sample headers exceed input limit",
            ));
        }
    }
    if method == "testHttp" {
        TestResources::try_acquire().map(Some)
    } else {
        Ok(None)
    }
}

fn plugin_conflict() -> InvokeFailure {
    InvokeFailure::invalid_request("httpPlugins is mutually exclusive with raw HTTP YAML fields")
}

fn check_managed_values(raw: &serde_json::value::RawValue) -> Result<(), InvokeFailure> {
    use crate::http_processing::config::{MAX_ADDENDUM, MAX_DOCUMENTS, MAX_PARAMETER_OVERRIDES};
    use serde_json::value::RawValue;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input<'a> {
        #[serde(borrow)]
        yaml: &'a RawValue,
        #[serde(borrow)]
        id: &'a RawValue,
        #[serde(borrow)]
        digest: &'a RawValue,
        #[serde(borrow)]
        parameters: Option<&'a RawValue>,
        #[serde(borrow)]
        permissions: Option<&'a RawValue>,
    }

    struct Plugins;
    impl<'de> de::Visitor<'de> for Plugins {
        type Value = ();

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded array of HTTP plugin inputs")
        }

        fn visit_seq<S: de::SeqAccess<'de>>(self, mut sequence: S) -> Result<(), S::Error> {
            let mut remaining = MAX_ADDENDUM;
            let mut overrides = MAX_PARAMETER_OVERRIDES * 6;
            let mut grants = 128_usize * 1024;
            let mut count = 0;
            while let Some(raw) = sequence.next_element::<&'de RawValue>()? {
                count += 1;
                if count > MAX_DOCUMENTS {
                    return Err(de::Error::custom("too many HTTP plugin documents"));
                }
                let input: Input<'_> =
                    serde_json::from_str(raw.get()).map_err(de::Error::custom)?;
                remaining -= super::bounded_json_string_len(input.yaml.get(), remaining)
                    .map_err(|error| de::Error::custom(error.message))?;
                super::check_json_string_limit(input.id.get(), 64)
                    .and_then(|()| super::check_json_string_limit(input.digest.get(), 64))
                    .map_err(|error| de::Error::custom(error.message))?;
                overrides = overrides
                    .checked_sub(input.parameters.map_or(0, |raw| raw.get().len()))
                    .ok_or_else(|| de::Error::custom("HTTP parameter input limit exceeded"))?;
                grants = grants
                    .checked_sub(input.permissions.map_or(0, |raw| raw.get().len()))
                    .ok_or_else(|| de::Error::custom("HTTP permission input limit exceeded"))?;
            }
            Ok(())
        }
    }

    if raw.get().len() > 6 * (MAX_ADDENDUM + MAX_PARAMETER_OVERRIDES) + 256 * 1024 {
        return Err(InvokeFailure::invalid_request(
            "HTTP plugin input limit exceeded",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    deserializer
        .deserialize_seq(Plugins)
        .map_err(|_| InvokeFailure::invalid_request("invalid HTTP plugin input or limit exceeded"))
}

pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(super) fn check_document_values(
    single: Option<&serde_json::value::RawValue>,
    multiple: Option<&serde_json::value::RawValue>,
) -> Result<(), InvokeFailure> {
    use crate::http_processing::MAX_ADDENDUM;
    const MAX_ARRAY_BYTES: usize = MAX_ADDENDUM * 6 + 64 * 1024;
    match (single, multiple) {
        (Some(_), Some(_)) => Err(InvokeFailure::invalid_request(
            "httpConfigYaml and httpConfigYamls are mutually exclusive",
        )),
        (Some(raw), None) => super::check_json_string_limit(raw.get(), MAX_ADDENDUM),
        (None, Some(raw)) if raw.get().len() <= MAX_ARRAY_BYTES => {
            struct Documents;
            impl<'de> de::Visitor<'de> for Documents {
                type Value = ();
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a bounded array of HTTP plugin YAML strings")
                }
                fn visit_seq<S: de::SeqAccess<'de>>(self, mut sequence: S) -> Result<(), S::Error> {
                    let mut remaining = MAX_ADDENDUM;
                    let mut count = 0;
                    while let Some(document) =
                        sequence.next_element::<&serde_json::value::RawValue>()?
                    {
                        count += 1;
                        if count > crate::http_processing::config::MAX_DOCUMENTS {
                            return Err(de::Error::custom("too many HTTP plugin documents"));
                        }
                        remaining -= super::bounded_json_string_len(document.get(), remaining)
                            .map_err(|error| de::Error::custom(error.message))?;
                    }
                    Ok(())
                }
            }
            let mut deserializer = serde_json::Deserializer::from_str(raw.get());
            deserializer.deserialize_seq(Documents).map_err(|_| {
                InvokeFailure::invalid_request(
                    "invalid httpConfigYamls array or plugin input limit exceeded",
                )
            })
        }
        (None, Some(_)) => Err(InvokeFailure::invalid_request(
            "httpConfigYamls exceeds input limit",
        )),
        (None, None) => Ok(()),
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct HttpContextInput {
    mitm_enabled: bool,
    exclude_domains: Vec<String>,
    rewrite_enabled: bool,
    js_enabled: bool,
    allow_intercept_only: bool,
    pub(crate) ca: Option<CaMaterial>,
}
impl Default for HttpContextInput {
    fn default() -> Self {
        Self::from_settings(HttpSettings::default(), None)
    }
}
impl HttpContextInput {
    pub(crate) fn from_settings(settings: HttpSettings, ca: Option<CaMaterial>) -> Self {
        Self {
            mitm_enabled: settings.mitm_enabled,
            exclude_domains: settings.exclude_domains,
            rewrite_enabled: settings.rewrite_enabled,
            js_enabled: settings.js_enabled,
            allow_intercept_only: settings.allow_intercept_only,
            ca,
        }
    }

    pub(crate) fn into_settings(self) -> (HttpSettings, Option<CaMaterial>) {
        (
            HttpSettings {
                mitm_enabled: self.mitm_enabled,
                exclude_domains: self.exclude_domains,
                rewrite_enabled: self.rewrite_enabled,
                js_enabled: self.js_enabled,
                allow_intercept_only: self.allow_intercept_only,
            },
            self.ca,
        )
    }
}
impl std::fmt::Debug for HttpContextInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpContextInput").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct StartPayload {
    pub(super) config_yaml: String,
    #[serde(default, deserialize_with = "present")]
    pub(super) http_config_yaml: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub(super) http_config_yamls: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    pub(super) http_plugins: Option<Vec<PluginInput>>,
    pub(super) http_context: Option<HttpContextInput>,
    #[serde(skip)]
    pub(super) cancellation: Option<CancellationToken>,
    #[serde(skip)]
    pub(super) foreground_overrides: super::foreground::ControllerOverrides,
    #[serde(skip)]
    pub(super) provider_paths: Option<Arc<crate::resource::paths::ProviderPaths>>,
    #[serde(skip)]
    pub(super) http_parameter_overrides: ParameterOverrides,
}

pub(super) type ParameterOverrides = BTreeMap<usize, BTreeMap<String, ParameterValue>>;

pub(super) enum HttpInputs {
    Raw(Vec<String>, ParameterOverrides),
    Managed(Vec<PluginInput>),
}

impl HttpInputs {
    pub(super) fn new(
        single: Option<String>,
        multiple: Option<Vec<String>>,
        managed: Option<Vec<PluginInput>>,
        overrides: ParameterOverrides,
    ) -> Result<Option<Self>, InvokeFailure> {
        let raw = document_inputs(single, multiple)?;
        match (raw, managed) {
            (Some(_), Some(_)) => Err(plugin_conflict()),
            (_, Some(plugins)) => Ok(Some(Self::Managed(plugins))),
            (Some(raw), None) => Ok(Some(Self::Raw(raw, overrides))),
            (None, None) if overrides.is_empty() => Ok(None),
            _ => Err(InvokeFailure::invalid_request(
                "HTTP parameters require plugins",
            )),
        }
    }

    pub(super) fn candidate(&self) -> Result<Option<Arc<PolicyCandidate>>, InvokeFailure> {
        let document = match self {
            Self::Raw(documents, overrides) => return candidate_raw(documents, overrides),
            Self::Managed(plugins) if plugins.is_empty() => return Ok(None),
            Self::Managed(plugins) => Document::parse_managed(plugins),
        };
        document
            .and_then(|document| document.compile())
            .map(Some)
            .map_err(|error| InvokeFailure::new(error.to_string()))
    }
}

pub(crate) fn document_inputs(
    single: Option<String>,
    multiple: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, InvokeFailure> {
    match (single, multiple) {
        (Some(_), Some(_)) => Err(InvokeFailure::invalid_request(
            "httpConfigYaml and httpConfigYamls are mutually exclusive",
        )),
        (Some(document), None) => Ok(Some(vec![document])),
        (None, documents) => Ok(documents),
    }
}

#[cfg(all(windows, feature = "windows-uwp"))]
pub(crate) fn candidate(
    documents: &[String],
) -> Result<Option<Arc<PolicyCandidate>>, InvokeFailure> {
    candidate_raw(documents, &ParameterOverrides::new())
}

pub(super) fn candidate_raw(
    documents: &[String],
    overrides: &ParameterOverrides,
) -> Result<Option<Arc<PolicyCandidate>>, InvokeFailure> {
    if documents.is_empty() && overrides.is_empty() {
        return Ok(None);
    }
    let document = if overrides.is_empty() {
        Document::parse_documents(documents)
    } else {
        Document::parse_overrides(documents, overrides)
    };
    document
        .and_then(|document| document.compile())
        .map(Some)
        .map_err(|error| InvokeFailure::new(error.to_string()))
}

pub(crate) fn bind(
    candidate: Option<&Arc<PolicyCandidate>>,
    context: Option<HttpContextInput>,
    cancellation: &CancellationToken,
) -> Result<Option<Arc<Policy>>, InvokeFailure> {
    let Some(candidate) = candidate else {
        return if context.is_some() {
            Err(InvokeFailure::invalid_request(
                "httpContext requires at least one HTTP plugin",
            ))
        } else {
            Ok(None)
        };
    };
    let (settings, ca) = context.unwrap_or_default().into_settings();
    candidate
        .prepare_platform(&settings, cancellation)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::Interrupted {
                InvokeFailure::from(error)
            } else {
                InvokeFailure::new("HTTP script preparation failed")
            }
        })?;
    candidate
        .bind_settings(&settings, ca.as_ref())
        .map(Some)
        .map_err(|_| InvokeFailure::new("invalid HTTP settings or private CA"))
}

pub(super) fn attach(
    config: &mut Config,
    inputs: Option<HttpInputs>,
    context: Option<HttpContextInput>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), InvokeFailure> {
    let candidate = inputs
        .as_ref()
        .map(HttpInputs::candidate)
        .transpose()?
        .flatten();
    let policy = bind(
        candidate.as_ref(),
        context,
        &cancellation.cloned().unwrap_or_default(),
    )?;
    config.set_http_policy(policy).map_err(InvokeFailure::from)
}

pub(super) fn static_policy(
    inputs: Option<HttpInputs>,
    context: Option<HttpContextInput>,
) -> Result<Option<Arc<Policy>>, InvokeFailure> {
    let Some(candidate) = inputs
        .as_ref()
        .map(HttpInputs::candidate)
        .transpose()?
        .flatten()
    else {
        return if context.is_some() {
            Err(InvokeFailure::invalid_request(
                "httpContext requires at least one HTTP plugin",
            ))
        } else {
            Ok(None)
        };
    };
    let (settings, ca) = context.unwrap_or_default().into_settings();
    if ca.is_some() {
        return Err(InvokeFailure::invalid_request(
            "this operation does not accept CA material",
        ));
    }
    Policy::for_evaluation(candidate, &settings)
        .map(Some)
        .map_err(|_| InvokeFailure::new("invalid HTTP settings"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_material_is_bounded_before_value_deserialization() {
        let oversized = serde_json::json!({
            "method":"start", "instanceId":"1", "payload":{
                "configYaml":"rules: ['MATCH,DIRECT']", "httpContext":{"ca":{
                    "certificate":"public", "privateKey":"x".repeat(crate::http_processing::private_context::MAX_CA_PEM_BYTES + 1)
                }}
            }
        }).to_string();
        assert!(check_envelope(&oversized).is_err());
        let validation = r#"{"method":"validateConfig","payload":{"configYaml":"","httpContext":{"ca":{"certificate":"public","privateKey":"secret"}}}}"#;
        assert!(check_envelope(validation).is_err());
    }
}
