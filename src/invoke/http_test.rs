//! Offline execution uses only explicit samples and prepared immutable content.
use super::*;
use crate::http_processing::{
    body::{self, OriginalRequestMeta, Transaction, WireBodyMeta},
    headers::{self, Fields},
    rules::{Phase, RuleAction, UrlAction},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TestPayload {
    http_config_yaml: String,
    http_context: Option<HttpContextInput>,
    url: String,
    request: Option<RequestSample>,
    response: Option<ResponseSample>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequestSample {
    #[serde(default = "get")]
    method: String,
    #[serde(default)]
    headers: Vec<[String; 2]>,
    body_base64: Option<String>,
}
fn get() -> String {
    "GET".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResponseSample {
    status: u16,
    #[serde(default)]
    headers: Vec<[String; 2]>,
    body_base64: Option<String>,
}

pub(crate) fn evaluate(payload: TestPayload) -> Result<Value, InvokeFailure> {
    let document = Document::parse(&payload.http_config_yaml)
        .map_err(|_| InvokeFailure::new("invalid HTTP processing configuration"))?;
    let (base, ca) = payload
        .http_context
        .map_or((None, None), |input| (input.base_dir, input.ca));
    if ca.is_some() {
        return Err(InvokeFailure::invalid_request(
            "testHttp does not accept CA material",
        ));
    }
    let base_dir = base.map(InvokePath::into_path);
    if base_dir.as_ref().is_some_and(|path| !path.is_absolute()) {
        return Err(InvokeFailure::invalid_request(
            "HTTP baseDir must be absolute",
        ));
    }
    let initialized = lock(&registry().runtime_data)
        .as_ref()
        .map(|data| (data.directory.root().to_owned(), data.http.clone()));
    let context = SourceContext {
        base_dir,
        data_dir: initialized.as_ref().map(|(root, _)| root.clone()),
        config_path: None,
    };
    let candidate = if document.unresolved_count() == 0 {
        Some(
            document
                .compile(&std::collections::BTreeMap::new())
                .map_err(InvokeFailure::from)?,
        )
    } else if let Some((_, store)) = initialized {
        store
            .try_lock()
            .map_err(|_| InvokeFailure::new("HTTP resource preparation is busy"))?
            .prepared(&document, &context)
            .map_err(InvokeFailure::from)?
    } else {
        None
    };
    let original = crate::http_processing::rules::offline_url(&payload.url)
        .map_err(|_| InvokeFailure::new("invalid HTTP test URL"))?;
    let Some(candidate) = candidate else {
        return Ok(
            json!({"resourcesReady":false,"outcome":"unprepared","originalUrl":original.as_str(),"httpsReady":false}),
        );
    };
    // Static binding intentionally omits CA: offline work never issues a leaf.
    let policy = Policy::for_evaluation(candidate.clone());
    let mut target = original.clone();
    let mut local = false;
    let mut url_stage = json!({"outcome":"unchanged"});
    let rules = policy.all_rules();
    for (index, rule) in rules.iter().enumerate() {
        match rule.evaluate_url(&original) {
            Ok(Some(action)) => {
                url_stage = match action {
                    UrlAction::Forward(url) => {
                        target = url;
                        json!({"outcome":"forward"})
                    }
                    UrlAction::Redirect { status, url } => {
                        target = url;
                        local = true;
                        json!({"outcome":"redirect","status":status})
                    }
                    UrlAction::Reject => {
                        local = true;
                        json!({"outcome":"reject","status":403})
                    }
                };
                url_stage["source"] = serde_json::to_value(candidate.origin(index))
                    .map_err(|_| InvokeFailure::new("HTTP result encoding failed"))?;
                break;
            }
            Err(_) => {
                local = true;
                url_stage = json!({"outcome":"failed","status":502});
                break;
            }
            Ok(None) => {}
        }
    }
    let request_headers = payload
        .request
        .as_ref()
        .map(|sample| fields(&sample.headers))
        .unwrap_or_default();
    headers::check(&request_headers)
        .map_err(|_| InvokeFailure::new("invalid HTTP request sample headers"))?;
    let method = payload
        .request
        .as_ref()
        .map_or("GET", |sample| sample.method.as_str());
    http::Method::from_bytes(method.as_bytes())
        .map_err(|_| InvokeFailure::new("invalid HTTP sample method"))?;
    let request_meta = OriginalRequestMeta::new(method, &request_headers);
    let mut stages = Vec::new();
    if !local {
        if let Some(sample) = payload.request {
            let cross_origin = original.origin() != target.origin();
            stages.push(sample_stage(
                &policy,
                &original,
                Phase::Request,
                fields(&sample.headers),
                sample.body_base64,
                &request_meta,
                None,
                cross_origin,
            )?);
        } else {
            stages.push(selected(&policy, &original, Phase::Request));
        }
        if let Some(sample) = payload.response {
            if !(100..600).contains(&sample.status) {
                return Err(InvokeFailure::new("invalid HTTP sample status"));
            }
            stages.push(sample_stage(
                &policy,
                &original,
                Phase::Response,
                fields(&sample.headers),
                sample.body_base64,
                &request_meta,
                Some(sample.status),
                false,
            )?);
        } else {
            stages.push(selected(&policy, &original, Phase::Response));
        }
    }
    Ok(
        json!({"resourcesReady":true,"httpsReady":false,"rewriteEnabled":document.rewrite.enabled,"mitmEnabled":document.mitm.enabled,"originalUrl":original.as_str(),"targetUrl":target.as_str(),"url":url_stage,"stages":stages}),
    )
}

fn fields(input: &[[String; 2]]) -> Fields {
    input
        .iter()
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect()
}
fn selected(policy: &Policy, original: &url::Url, phase: Phase) -> Value {
    let selected: Vec<_> = policy.all_rules().iter().enumerate().filter_map(|(index, rule)| {
        let matches_phase = matches!(&rule.action, RuleAction::Header{phase:p,..}|RuleAction::Body{phase:p,..} if *p==phase);
        (matches_phase && rule.matches(original)).then(|| json!({"source":policy.candidate().and_then(|candidate| candidate.origin(index)),"name":rule.name,"outcome":"selected"}))
    }).collect();
    json!({"phase":if phase==Phase::Request {"request"} else {"response"},"rules":selected})
}
#[allow(clippy::too_many_arguments)]
fn sample_stage(
    policy: &Policy,
    original: &url::Url,
    phase: Phase,
    mut output: Fields,
    body: Option<String>,
    request: &OriginalRequestMeta,
    status: Option<u16>,
    cross_origin: bool,
) -> Result<Value, InvokeFailure> {
    headers::check(&output).map_err(|_| InvokeFailure::new("invalid HTTP sample headers"))?;
    let wire_fields = output.clone();
    if cross_origin {
        headers::strip_origin_credentials(&mut output);
    }
    let header_outcome = headers::apply(policy.all_rules(), original, phase, &mut output);
    let mut result = selected(policy, original, phase);
    result["headersOutcome"] = json!(format!("{header_outcome:?}"));
    if let Some(encoded) = body {
        if encoded.len() > body::MAX_BODY.div_ceil(3) * 4 {
            return Err(InvokeFailure::new("HTTP sample body exceeds limit"));
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| InvokeFailure::new("invalid HTTP bodyBase64"))?;
        let wire = WireBodyMeta::new(
            &wire_fields,
            request,
            phase,
            status,
            Some(bytes.len() as u64),
            status == Some(101),
        );
        match Transaction::begin(
            policy.body_budget(),
            policy.all_rules(),
            original,
            phase,
            &wire,
        ) {
            Ok(mut transaction) => {
                transaction
                    .push(&bytes)
                    .map_err(|_| InvokeFailure::new("HTTP sample body exceeds limit"))?;
                let mut body = transaction.finish(false);
                body.finalize_headers(&mut output);
                result["bodyOutcome"] = json!(if body.changed {
                    "changed"
                } else if body.bypass.is_some() {
                    "bypassed"
                } else {
                    "unchanged"
                });
                result["bodyBase64"] = json!(STANDARD.encode(body.body.as_ref()));
                if let Some(reason) = body.bypass {
                    result["bypassReason"] = json!(format!("{reason:?}"));
                }
            }
            Err(reason) => {
                result["bodyOutcome"] = json!("bypassed");
                result["bypassReason"] = json!(format!("{reason:?}"));
                result["bodyBase64"] = json!(STANDARD.encode(bytes));
            }
        }
    } else {
        result["bodyOutcome"] = json!("not-provided");
    }
    result["headers"] = json!(output);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(input: Value) -> Value {
        evaluate(serde_json::from_value(input).unwrap()).unwrap()
    }
    #[test]
    fn unprepared_external_rules_are_distinct_from_no_match() {
        let result = run(
            json!({"httpConfigYaml":"rewrite-providers: {missing: {type: file, path: no-io.yaml}}\nrewrite: {rules: [{rule-set: missing}]}","url":"https://example.com/"}),
        );
        assert_eq!(result["resourcesReady"], false);
        assert_eq!(result["outcome"], "unprepared");
    }
}
