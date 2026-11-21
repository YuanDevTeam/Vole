//! Offline execution uses only explicit samples and prepared immutable content.
use super::*;
use crate::http_processing::{
    body::{self, Budget, BudgetedBytes, OriginalRequestMeta, Transaction, WireBodyMeta},
    body_budget::Reservation,
    headers::{self, Fields},
    rules::{HeaderView, Phase, RequestMatch, Rule, RuleAction, UrlAction},
    script_config::{BodyMode, CompiledScript},
    script_message::{
        self, LocalResponse, Message, OriginalSnapshot, Outcome, RequestSnapshot, ResponseSnapshot,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, SemaphorePermit};

static TEST_HTTP_SLOTS: Semaphore = Semaphore::const_new(2);

/// Keep shared body charges and admission through Invoke's JSON serialization.
pub(in crate::invoke) struct TestResources {
    _permit: SemaphorePermit<'static>,
    encoded: Vec<Reservation>,
}

impl std::fmt::Debug for TestResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestResources").finish_non_exhaustive()
    }
}

impl TestResources {
    pub(super) fn try_acquire() -> Result<Self, InvokeFailure> {
        let permit = TEST_HTTP_SLOTS
            .try_acquire()
            .map_err(|_| InvokeFailure::invalid_state("testHttp is busy"))?;
        Ok(Self {
            _permit: permit,
            encoded: Vec::new(),
        })
    }

    fn encode_body(&mut self, budget: &Budget, body: &[u8]) -> Result<String, InvokeFailure> {
        let encoded = body.len().div_ceil(3) * 4;
        // The intermediate JSON value and the serialized response coexist.
        let reservation = budget.reserve(encoded * 2).ok_or_else(body_budget_error)?;
        let result = STANDARD.encode(body);
        self.encoded.push(reservation);
        Ok(result)
    }
}

fn body_budget_error() -> InvokeFailure {
    InvokeFailure::new("testHttp body workspace exceeded")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TestPayload {
    #[serde(default, deserialize_with = "present")]
    http_config_yaml: Option<String>,
    #[serde(default, deserialize_with = "present")]
    http_config_yamls: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    http_plugins: Option<Vec<PluginInput>>,
    http_context: Option<HttpContextInput>,
    url: String,
    #[serde(default)]
    execute_scripts: bool,
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

pub(in crate::invoke) fn evaluate(
    payload: TestPayload,
    mut resources: TestResources,
) -> Result<(Value, TestResources), InvokeFailure> {
    // Synchronous Invoke can be called by a host that is already running a
    // Tokio executor. Join our own bounded, timer-only executor before return.
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("vole-http-sample".into())
            .spawn_scoped(scope, move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .map_err(InvokeFailure::from)?;
                    let data = runtime.block_on(evaluate_samples(payload, &mut resources))?;
                    Ok((data, resources))
                })
            })
            .map_err(InvokeFailure::from)?;
        worker
            .join()
            .map_err(|_| InvokeFailure::internal("HTTP sample worker failed"))?
    })
}

async fn evaluate_samples(
    payload: TestPayload,
    resources: &mut TestResources,
) -> Result<Value, InvokeFailure> {
    let inputs = HttpInputs::new(
        payload.http_config_yaml,
        payload.http_config_yamls,
        payload.http_plugins,
        Default::default(),
    )?;
    let policy = static_policy(inputs, payload.http_context)?.ok_or_else(|| {
        InvokeFailure::invalid_request("testHttp requires at least one HTTP plugin")
    })?;
    let candidate = policy.candidate();
    let original = crate::http_processing::rules::offline_url(&payload.url)
        .map_err(|_| InvokeFailure::new("invalid HTTP test URL"))?;
    let eligible = policy.allows_target(&original);
    let method = payload
        .request
        .as_ref()
        .map_or_else(|| "GET".to_owned(), |sample| sample.method.clone());
    http::Method::from_bytes(method.as_bytes())
        .map_err(|_| InvokeFailure::new("invalid HTTP sample method"))?;
    let request_headers = payload
        .request
        .as_ref()
        .map(|sample| fields(&sample.headers))
        .unwrap_or_default();
    headers::check(&request_headers)
        .map_err(|_| InvokeFailure::new("invalid HTTP request sample headers"))?;
    let request_meta = OriginalRequestMeta::new(&method, &request_headers);
    let request_mask = payload.request.as_ref().map_or(0, |_| {
        policy.request_conditions(HeaderView::Fields(&request_headers))
    });
    let selection =
        RequestMatch::from((&original, method.as_str())).with_conditions(request_mask, 0);
    let allow_respond = method != "CONNECT"
        && !request_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    let mut target = original.clone();
    let mut local = false;
    let mut url_stage = json!({"outcome":"unchanged"});
    let rules = if eligible { policy.rules() } else { &[] };
    for (index, rule) in rules.iter().enumerate() {
        match rule.evaluate_url(selection) {
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
                    UrlAction::Respond(reply) if allow_respond => {
                        local = true;
                        let mut reply = LocalResponse::from_static(
                            &reply,
                            method == "HEAD",
                            request_meta.identity_allowed,
                            policy.body_budget(),
                        );
                        if policy.h3_fallback_for_url(&original) {
                            headers::alt_svc::filter_fields(&mut reply.headers);
                        }
                        json!({"outcome":"respond","status":reply.status,"headers":reply.headers,
                            "bodyBase64":resources.encode_body(policy.body_budget(), &reply.body)?})
                    }
                    UrlAction::Respond(_) => continue,
                };
                url_stage["source"] =
                    serde_json::to_value(candidate.and_then(|candidate| candidate.origin(index)))
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
    let mut stages = Vec::new();
    let mut terminal = None;
    let mut final_method = method.clone();
    if !local {
        let exchange = Exchange {
            policy: &policy,
            rules,
            original: OriginalSnapshot {
                url: original.clone(),
                method: method.clone(),
                identity_allowed: request_meta.identity_allowed,
                asterisk: false,
            },
            request_meta,
            execute_scripts: payload.execute_scripts,
        };
        if payload.execute_scripts && payload.request.is_none() && eligible {
            let potential = selection.with_conditions(u64::MAX, u64::MAX);
            if policy
                .scripts()
                .iter()
                .any(|script| script.matches(potential))
            {
                return Err(InvokeFailure::invalid_request(
                    "executing JS requires a request sample",
                ));
            }
        }
        let mut request = RequestSnapshot {
            url: target,
            method: method.clone(),
            headers: request_headers.clone(),
        };
        if let Some(sample) = payload.request {
            let cross_origin = !script_message::same_origin(&original, &request.url);
            let message = Message::request(
                exchange.original.clone(),
                request,
                None,
                &request_headers,
                cross_origin,
            )
            .with_conditions(request_mask, 0);
            let result = exchange
                .stage(
                    message,
                    request_headers,
                    sample.body_base64,
                    selection,
                    resources,
                )
                .await?;
            request = result.request;
            terminal = result.terminal;
            stages.push(result.data);
        } else {
            let possible = selection.with_conditions(u64::MAX, 0);
            stages.push(exchange.preview(Phase::Request, possible, "request"));
        }
        target = request.url.clone();
        final_method = request.method.clone();
        if terminal.is_none() {
            let response = payload.response;
            if let Some(sample) = response {
                if !(100..600).contains(&sample.status) {
                    return Err(InvokeFailure::invalid_request("invalid HTTP sample status"));
                }
                let headers = fields(&sample.headers);
                validate_headers(&headers)?;
                let mask = policy.response_conditions(sample.status, HeaderView::Fields(&headers));
                let response_selection = selection.with_conditions(request_mask, mask);
                let message = Message::response(
                    exchange.original.clone(),
                    request,
                    ResponseSnapshot {
                        status: sample.status,
                        headers: headers.clone(),
                    },
                    None,
                    &headers,
                )
                .with_conditions(request_mask, mask);
                let result = exchange
                    .stage(
                        message,
                        headers,
                        sample.body_base64,
                        response_selection,
                        resources,
                    )
                    .await?;
                terminal = result.terminal;
                stages.push(result.data);
            } else {
                let response_selection = selection.with_conditions(request_mask, u64::MAX);
                if payload.execute_scripts
                    && exchange.has_actions(Phase::Response, response_selection)
                {
                    return Err(InvokeFailure::invalid_request(
                        "executing the response stage requires a response sample",
                    ));
                }
                stages.push(exchange.preview(Phase::Response, response_selection, "response"));
            }
        }
    }
    Ok(json!({
        "resourcesReady": true,
        "httpsReady": false,
        "targetEligible": eligible,
        "rewriteEnabled": policy.settings().rewrite_enabled,
        "mitmEnabled": policy.settings().mitm_enabled,
        "originalUrl": original.as_str(),
        "targetUrl": target.as_str(),
        "targetMethod": final_method,
        "url": url_stage,
        "executeScripts": payload.execute_scripts,
        "terminal": terminal,
        "stages": stages
    }))
}

fn fields(input: &[[String; 2]]) -> Fields {
    input
        .iter()
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect()
}

fn validate_headers(fields: &Fields) -> Result<(), InvokeFailure> {
    headers::check(fields)
        .map_err(|_| InvokeFailure::invalid_request("invalid HTTP sample headers"))
}

struct Exchange<'a> {
    policy: &'a Policy,
    rules: &'a [Rule],
    original: OriginalSnapshot,
    request_meta: OriginalRequestMeta,
    execute_scripts: bool,
}

struct StageResult {
    data: Value,
    request: RequestSnapshot,
    terminal: Option<Value>,
}

impl Exchange<'_> {
    fn native_rules<'a>(
        &'a self,
        phase: Phase,
        selection: RequestMatch<'a>,
    ) -> impl Iterator<Item = (usize, &'a Rule)> + 'a {
        self.rules.iter().enumerate().filter(move |(_, rule)| {
            matches!(&rule.action, RuleAction::Header { phase: p, .. } | RuleAction::Body { phase: p, .. } if *p == phase)
                && rule.matches(selection)
        })
    }

    fn scripts<'a>(
        &'a self,
        phase: Phase,
        selection: RequestMatch<'a>,
    ) -> impl Iterator<Item = &'a CompiledScript> + 'a {
        self.policy.scripts().iter().filter(move |script| {
            script.phase == phase
                && self.policy.allows_target(selection.url)
                && script.matches(selection)
        })
    }

    fn has_actions(&self, phase: Phase, selection: RequestMatch<'_>) -> bool {
        self.native_rules(phase, selection).next().is_some()
            || self.scripts(phase, selection).next().is_some()
    }

    fn script_event(&self, script: &CompiledScript, outcome: &str, reason: Option<&str>) -> Value {
        let mut event = json!({
            "source": script.location,
            "id": self.policy.document().rule_id(script.location),
            "name": script.name,
            "body": script.body,
            "outcome": outcome,
        });
        if let Some(reason) = reason {
            event["reason"] = json!(reason);
        }
        event
    }

    fn selected(&self, phase: Phase, selection: RequestMatch<'_>, outcome: &str) -> Value {
        let rules: Vec<_> = self
            .native_rules(phase, selection)
            .map(|(index, rule)| {
                let source = self
                    .policy
                    .candidate()
                    .and_then(|candidate| candidate.origin(index));
                json!({
                    "source":source,
                    "id":source.and_then(|source| self.policy.document().rule_id(*source)),
                    "name":rule.name,
                    "outcome":outcome
                })
            })
            .collect();
        let scripts: Vec<_> = self
            .scripts(phase, selection)
            .map(|script| self.script_event(script, "not-run", None))
            .collect();
        json!({"phase": phase_name(phase), "rules": rules, "scripts": scripts})
    }

    fn preview(&self, phase: Phase, selection: RequestMatch<'_>, sample: &str) -> Value {
        let mut preview = self.selected(phase, selection, "potential");
        preview["sampleRequired"] = json!(self.has_actions(phase, selection).then_some(sample));
        preview
    }

    async fn stage(
        &self,
        mut message: Message,
        wire_headers: Fields,
        body: Option<String>,
        selection: RequestMatch<'_>,
        resources: &mut TestResources,
    ) -> Result<StageResult, InvokeFailure> {
        let phase = message.phase();
        let mut data = self.selected(phase, selection, "selected");
        let fields = match &mut message.response {
            Some(response) => &mut response.headers,
            None => &mut message.request.headers,
        };
        if phase == Phase::Request && message.crossed_origin {
            headers::strip_origin_credentials(fields);
        }
        let header_outcome = headers::apply(self.rules, selection, phase, fields);
        data["headersOutcome"] = json!(format!("{header_outcome:?}"));

        let budget = self.policy.body_budget();
        let mut bytes = None;
        let mut bypass = None;
        let mut changed = false;
        let mut script_events = Vec::new();
        let has_scripts = self.execute_scripts && self.scripts(phase, selection).next().is_some();
        if let Some(encoded) = body {
            let sample = decode_body(&encoded, budget)?;
            let status = message.response.as_ref().map(|response| response.status);
            let fields = match &mut message.response {
                Some(response) => &mut response.headers,
                None => &mut message.request.headers,
            };
            let wire = WireBodyMeta::new(
                &wire_headers,
                &self.request_meta,
                phase,
                status,
                Some(sample.as_ref().len() as u64),
                status == Some(101),
            );
            if has_scripts {
                let script_body = self
                    .scripts(phase, selection)
                    .any(|s| s.body != BodyMode::None);
                match Transaction::begin_shared(
                    budget,
                    self.rules,
                    selection,
                    phase,
                    &wire,
                    script_body,
                ) {
                    Ok(mut transaction) => {
                        transaction
                            .push(sample.as_ref())
                            .map_err(|_| body_budget_error())?;
                        drop(sample);
                        message.body = Some(transaction.finish_shared(false, fields));
                    }
                    Err(reason) => {
                        bypass = Some(reason);
                        bytes = Some(sample);
                    }
                }
            } else {
                match Transaction::begin(budget, self.rules, selection, phase, &wire) {
                    Ok(mut transaction) => {
                        transaction
                            .push(sample.as_ref())
                            .map_err(|_| body_budget_error())?;
                        drop(sample);
                        let mut result = transaction.finish(false);
                        result.finalize_headers(fields);
                        bypass = result.bypass;
                        changed = result.changed;
                        bytes = Some(result.body);
                    }
                    Err(reason) => {
                        bypass = Some(reason);
                        bytes = Some(sample);
                    }
                }
            }
        }

        let outcome = if has_scripts {
            let cancellation = CancellationToken::new();
            let mut observe = |script: &CompiledScript, result, reason| {
                script_events.push(self.script_event(script, result, reason));
            };
            #[cfg(target_vendor = "apple")]
            let available = crate::http_processing::scripts::ensure_available();
            #[cfg(not(target_vendor = "apple"))]
            let available = crate::http_processing::scripts::prepare_platform(&cancellation);
            let outcome = match available {
                Ok(()) => {
                    script_message::run_observed(
                        self.policy,
                        &mut message,
                        &cancellation,
                        &mut observe,
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            let mut pending = data["scripts"]
                .as_array_mut()
                .expect("script preview array")
                .split_off(script_events.len());
            script_events.append(&mut pending);
            data["scripts"] = json!(script_events);
            outcome
        } else {
            Ok(Outcome::Forward)
        };

        let terminal = match outcome {
            Ok(Outcome::Forward) => None,
            Ok(Outcome::Respond(mut response)) => {
                if self.policy.h3_fallback_for_url(&self.original.url) {
                    headers::alt_svc::filter_fields(&mut response.headers);
                }
                Some(json!({
                    "phase":phase_name(phase), "outcome":"respond", "status":response.status,
                    "headers":response.headers,
                    "bodyBase64":resources.encode_body(budget, &response.body)?
                }))
            }
            Ok(Outcome::Abort) => Some(json!({"phase":phase_name(phase), "outcome":"abort"})),
            Err(error) => Some(
                json!({"phase":phase_name(phase), "outcome":"failed", "reason": match error.kind() {
                    io::ErrorKind::TimedOut => "stage-timeout",
                    io::ErrorKind::Interrupted => "cancelled",
                    io::ErrorKind::Unsupported => "backend-unavailable",
                    _ => "backend-fatal",
                }}),
            ),
        };

        if let Some(entity) = &message.body {
            bypass = entity.bypass;
            changed = entity.changed();
        }
        let output_body = message
            .body
            .as_ref()
            .map(|entity| entity.wire().as_ref())
            .or_else(|| bytes.as_ref().map(|body| body.as_ref()));
        data["bodyOutcome"] = json!(if changed {
            "changed"
        } else if bypass.is_some() {
            "bypassed"
        } else if output_body.is_some() {
            "unchanged"
        } else {
            "not-provided"
        });
        if let Some(reason) = bypass {
            data["bypassReason"] = json!(format!("{reason:?}"));
        }
        if terminal.is_none()
            && let Some(output) = output_body
        {
            data["bodyBase64"] = json!(resources.encode_body(budget, output)?);
        }
        if let Some(mut response) = message.response {
            if self.policy.h3_fallback_for_url(&self.original.url) {
                headers::alt_svc::filter_fields(&mut response.headers);
            }
            data["status"] = json!(response.status);
            data["headers"] = json!(response.headers);
        } else {
            data["url"] = json!(message.request.url.as_str());
            data["method"] = json!(message.request.method);
            data["headers"] = json!(message.request.headers);
        }
        Ok(StageResult {
            data,
            request: message.request,
            terminal,
        })
    }
}

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Request => "request",
        Phase::Response => "response",
    }
}

fn decode_body(input: &str, budget: &Budget) -> Result<BudgetedBytes, InvokeFailure> {
    let length = input.len();
    if length > body::MAX_BODY.div_ceil(3) * 4 {
        return Err(InvokeFailure::invalid_request(
            "HTTP sample body exceeds limit",
        ));
    }
    if !length.is_multiple_of(4) {
        return Err(InvokeFailure::invalid_request("invalid HTTP bodyBase64"));
    }
    let padding = if input.ends_with("==") {
        2
    } else {
        usize::from(input.ends_with('='))
    };
    let capacity = length / 4 * 3 - padding;
    if capacity > body::MAX_BODY {
        return Err(InvokeFailure::invalid_request(
            "HTTP sample body exceeds limit",
        ));
    }
    let mut body = BudgetedBytes::new(budget, capacity).ok_or_else(body_budget_error)?;
    body.write_initialized_output(capacity, |output| {
        STANDARD
            .decode_slice(input, output)
            .map_err(io::Error::other)
    })
    .map_err(|_| InvokeFailure::invalid_request("invalid HTTP bodyBase64"))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    static OFFLINE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const REWRITE: &str = r#"targets:
  - origins: [http://old.example]
    rules:
      - match: {method: POST, path-exact: /a}
        request:
          url: {replace: 'http://new.example/b'}
          headers: [{set: {x-test: selected}}]
"#;
    const SCRIPT: &str = r#"targets:
  - origins: [http://old.example]
    rules:
      - request:
          js:
            source: |
              function rewrite(input) { return {type: "pass"}; }
"#;

    fn run(input: Value) -> Value {
        let _guard = OFFLINE_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        evaluate(
            serde_json::from_value(input).unwrap(),
            TestResources::try_acquire().unwrap(),
        )
        .unwrap()
        .0
    }

    #[cfg(any(
        target_vendor = "apple",
        all(feature = "http-js-quickjs", any(target_os = "linux", windows))
    ))]
    #[test]
    fn platform_fixture_rewrites_each_origin_through_test_http() {
        let yaml = include_str!("../../tests/fixtures/http-js-platform.yaml");
        for origin in [
            "http://js-rewrite.test:18080",
            "https://js-rewrite.test:18443",
            "https://js-rewrite.test:18444",
        ] {
            let result = run(json!({
                "httpConfigYaml": yaml,
                "httpContext": {"mitmEnabled":true},
                "executeScripts": true,
                "url": format!("{origin}/rewrite"),
                "request": {
                    "method": "POST",
                    "headers": [["content-type", "application/octet-stream"]],
                    "bodyBase64": STANDARD.encode("probe")
                },
                "response": {
                    "status": 200,
                    "headers": [["content-type", "text/plain; charset=utf-8"]],
                    "bodyBase64": STANDARD.encode("origin:probe:js")
                }
            }));
            assert!(result["terminal"].is_null(), "{result:#}");
            let stages = &result["stages"];
            assert_eq!(stages[0]["scripts"][0]["outcome"], "accepted", "{result:#}");
            assert_eq!(stages[0]["bodyBase64"], STANDARD.encode("probe:js"));
            assert_eq!(stages[1]["scripts"][0]["outcome"], "accepted", "{result:#}");
            assert_eq!(
                stages[1]["scripts"][1]["outcome"], "rolled-back",
                "{result:#}"
            );
            assert_eq!(
                stages[1]["bodyBase64"],
                STANDARD.encode("origin:probe:js:改写")
            );
        }
        let local = run(json!({
            "httpConfigYaml": yaml,
            "executeScripts": true,
            "url": "http://js-rewrite.test:18080/local",
            "request": {}
        }));
        assert_eq!(local["terminal"]["status"], 202, "{local:#}");
        assert_eq!(local["terminal"]["bodyBase64"], STANDARD.encode("local-js"));
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn p1_terminal_script_skips_response_sample_validation_and_later_scripts() {
        let yaml = r#"
targets:
  - origins: [http://old.example]
    rules:
      - id: respond
        request:
          js:
            source: |
              function rewrite(input) {
                return {type: "respond", status: 201, body: {kind: "text", data: "local"}};
              }
      - id: skipped
        request:
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
        response:
          headers: [{set: {x-origin: upstream}}]
"#;
        let mut input = json!({"httpConfigYaml":yaml, "url":"http://old.example/a"});
        let preview = run(input.clone());
        assert_eq!(preview["stages"][0]["sampleRequired"], "request");
        assert_eq!(preview["stages"][0]["scripts"][0]["outcome"], "not-run");
        input["executeScripts"] = true.into();
        input["request"] = json!({});
        input["response"] = json!({"status": 600});
        let result = run(input);
        assert_eq!(result["terminal"]["outcome"], "respond");
        assert_eq!(result["terminal"]["status"], 201);
        assert_eq!(result["terminal"]["bodyBase64"], "bG9jYWw=");
        assert_eq!(result["stages"].as_array().unwrap().len(), 1);
        assert_eq!(result["stages"][0]["scripts"][0]["id"], "respond");
        assert_eq!(result["stages"][0]["scripts"][0]["outcome"], "respond");
        assert_eq!(result["stages"][0]["scripts"][1]["outcome"], "not-run");
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn p1_offline_keeps_successful_stages_and_distinguishes_missing_body() {
        let yaml = r#"
targets:
  - origins: [http://old.example]
    rules:
      - id: invalid
        request:
          headers: [{set: {x-native: kept}}]
          js:
            source: |
              function rewrite(input) {
                return {type:"modify", url:"http://old.example/no-commit",
                  headers:[{op:"set", name:"content-length", values:["9"]}]};
              }
      - id: body
        request:
          js:
            body: bytes
            source: |
              function rewrite(input) {
                if (input.body.data.length !== 0) return {type:"abort"};
                return {type:"modify", url:"http://old.example/empty"};
              }
"#;
        let mut input = json!({"httpConfigYaml":yaml, "url":"http://old.example/a", "executeScripts":true, "request":{}});
        let missing = run(input.clone());
        let stage = &missing["stages"][0];
        assert_eq!(missing["targetUrl"], "http://old.example/a");
        assert_eq!(stage["headers"], json!([["x-native", "kept"]]));
        assert_eq!(stage["bodyOutcome"], "not-provided");
        assert_eq!(stage["scripts"][0]["outcome"], "rolled-back");
        assert_eq!(stage["scripts"][1]["reason"], "body-unavailable");
        input["request"]["bodyBase64"] = "".into();
        let empty = run(input);
        assert_eq!(empty["targetUrl"], "http://old.example/empty");
        assert_eq!(empty["stages"][0]["scripts"][1]["outcome"], "accepted");
        assert_eq!(empty["stages"][0]["bodyBase64"], "");
    }

    #[test]
    fn offline_pipeline_uses_original_url_and_method_in_all_stages() {
        let result = run(json!({
            "httpConfigYaml": REWRITE, "url": " http://old.example/a#fragment ",
            "request": {"method":"POST", "headers":[["Authorization","old-secret"],["Cookie","old-cookie"]]}
        }));
        assert_eq!(result["targetUrl"], "http://new.example/b");
        assert_eq!(
            result["stages"][0]["headers"],
            json!([["x-test", "selected"]])
        );
        assert_eq!(result["httpsReady"], false);
        for url in ["http://different.example/a", "http://old.example/a"] {
            let result =
                run(json!({"httpConfigYaml":REWRITE,"url":url,"request":{"method":"GET"}}));
            assert_eq!(result["targetUrl"], url);
            assert_eq!(result["stages"][0]["headers"], json!([]));
        }
    }

    #[test]
    fn offline_marks_unexecuted_scripts_and_evaluates_native_actions() {
        let input = json!({"httpConfigYamls":[REWRITE,SCRIPT], "url":"http://old.example/a", "request":{"method":"POST"}});
        assert_eq!(
            run(input.clone())["stages"][0]["scripts"][0]["outcome"],
            "not-run"
        );
        let mut disabled = input;
        disabled["httpContext"] = json!({"jsEnabled":false});
        assert_eq!(run(disabled)["targetUrl"], "http://new.example/b");
    }

    #[test]
    fn p0_a_managed_plugin_cannot_borrow_another_plugins_https_scope() {
        use sha2::{Digest, Sha256};
        let denied = "targets: [{origins: ['https://*.cdn.example.com'], rules: [{response: {headers: [{set: {x-denied: yes}}]}}]}]";
        let allowed = "targets: [{origins: ['https://api.cdn.example.com'], rules: [{response: {headers: [{set: {x-allowed: yes}}]}}]}]";
        let result = run(json!({
            "url":"https://api.cdn.example.com/v1",
            "httpContext":{"mitmEnabled":true},
            "httpPlugins":[
                {"id":"denied","yaml":denied,"digest":Sha256::digest(denied.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>()},
                {"id":"approved","yaml":allowed,"digest":Sha256::digest(allowed.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    "permissions":{"httpsOrigins":["https://api.cdn.example.com:443"]}}
            ],
            "response":{"status":200}
        }));
        assert_eq!(result["targetEligible"], true);
        assert_eq!(
            result["stages"][1]["headers"],
            json!([["x-allowed", "yes"]])
        );
    }

    #[test]
    fn p0_local_response_is_terminal_for_offline_samples() {
        let yaml = "targets: [{origins: ['http://example.com'], rules: [{match: {request-headers: [{name: x-mode, equals: mock}]}, request: {respond: {status: 200, body: {base64: AAAAAAA=}}}}, {request: {url: {reject: true}}}]}]";
        let input = json!({"url":"http://example.com/v1","httpConfigYaml":yaml,
            "request":{"headers":[["X-Mode","mock"]]}, "response":{"status":600}});
        let result = run(input);
        assert_eq!(result["url"]["outcome"], "respond");
        assert_eq!(result["url"]["bodyBase64"], "AAAAAAA=");
        assert_eq!(result["stages"], json!([]));
        assert_eq!(
            run(json!({"url":"http://example.com/v1","httpConfigYaml":yaml}))["url"]["status"],
            403
        );
    }

    #[test]
    fn h3_alt_svc_filter_runs_after_the_original_response_match() {
        let yaml = r#"
targets:
  - origins: ['https://www.example.com']
    rules:
      - response:
          when:
            headers: [{name: alt-svc, regex: '^h3='}]
          headers: [{set: {x-original-alt-svc: yes}}]
"#;
        let advertised = "h3=\":443\", h2=\":8443\"";
        let mut sample = json!({
            "httpConfigYaml": yaml,
            "httpContext": {"mitmEnabled": true},
            "url": "https://www.example.com/",
            "request": {},
            "response": {"status": 200, "headers": [["alt-svc", advertised]]},
        });
        let transformed = run(sample.clone());
        assert_eq!(
            transformed["stages"][1]["headers"],
            json!([["alt-svc", "h2=\":8443\""], ["x-original-alt-svc", "yes"]])
        );
        sample["httpContext"]["rewriteEnabled"] = false.into();
        assert_eq!(
            run(sample)["stages"][1]["headers"],
            json!([["alt-svc", advertised]])
        );
    }
}
