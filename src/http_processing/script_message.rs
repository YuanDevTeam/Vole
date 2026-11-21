//! Shared script message transactions. HTTP adapters retain framing and I/O.
use super::{
    Policy,
    body::{self, Budget, BudgetedBytes, Entity, MAX_BODY},
    body_budget::Reservation,
    headers::{self, Fields},
    rules::{self, Phase, RequestMatch, StaticResponse},
    script_config::{BodyMode, CompiledScript},
};
use bytes::Bytes;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone)]
pub(crate) struct OriginalSnapshot {
    pub(crate) url: Url,
    pub(crate) method: String,
    pub(crate) identity_allowed: bool,
    pub(crate) asterisk: bool,
}

#[derive(Clone)]
pub(crate) struct RequestSnapshot {
    pub(crate) url: Url,
    pub(crate) method: String,
    pub(crate) headers: Fields,
}

#[derive(Clone)]
pub(crate) struct ResponseSnapshot {
    pub(crate) status: u16,
    pub(crate) headers: Fields,
}

pub(crate) struct Message {
    pub(crate) original: OriginalSnapshot,
    pub(crate) request: RequestSnapshot,
    pub(crate) response: Option<ResponseSnapshot>,
    pub(crate) body: Option<Entity>,
    /// Sticky: original trailers must not restore credentials after A→B→A.
    pub(crate) crossed_origin: bool,
    protected: BTreeSet<String>,
    partial_response: bool,
    conditions: (u64, u64),
}

pub(crate) struct LocalResponse {
    pub(crate) status: u16,
    pub(crate) headers: Fields,
    pub(crate) body: Bytes,
}

struct StaticBodyOwner {
    body: Bytes,
    _reservation: Reservation,
}

impl AsRef<[u8]> for StaticBodyOwner {
    fn as_ref(&self) -> &[u8] {
        &self.body
    }
}

impl LocalResponse {
    pub(crate) fn from_static(
        response: &StaticResponse,
        head: bool,
        identity_allowed: bool,
        budget: &Budget,
    ) -> Self {
        let empty = |status| Self {
            status,
            headers: (!head)
                .then(|| ("content-length".into(), "0".into()))
                .into_iter()
                .collect(),
            body: Bytes::new(),
        };
        let mut headers = response.headers.clone();
        let mut body = Bytes::new();
        if !head && !matches!(response.status, 204 | 304) {
            let length = response.body.len();
            if length > 0 {
                if !identity_allowed {
                    return empty(406);
                }
                let Some(reservation) = budget.reserve(length) else {
                    return empty(503);
                };
                // Retain the reservation until even H2's queued slices have
                // released the immutable configuration bytes.
                body = Bytes::from_owner(StaticBodyOwner {
                    body: response.body.clone(),
                    _reservation: reservation,
                });
            }
            headers.push(("content-length".into(), length.to_string()));
        }
        if headers::check(&headers).is_err() {
            return empty(503);
        }
        Self {
            status: response.status,
            headers,
            body,
        }
    }
}

pub(crate) enum Outcome {
    Forward,
    Respond(LocalResponse),
    Abort,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BodyKind {
    Text,
    Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyOutput {
    pub(crate) kind: BodyKind,
}

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)?
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("null is not an omitted script field"))
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum HeaderOp {
    Set { name: String, values: Vec<String> },
    Add { name: String, values: Vec<String> },
    Remove { name: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderField {
    name: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ScriptOutput {
    Pass {},
    Modify {
        #[serde(default, deserialize_with = "present")]
        url: Option<String>,
        #[serde(default, deserialize_with = "present")]
        method: Option<String>,
        #[serde(default, deserialize_with = "present")]
        status: Option<u16>,
        #[serde(default, deserialize_with = "present")]
        headers: Option<Vec<HeaderOp>>,
        #[serde(default, deserialize_with = "present")]
        body: Option<BodyOutput>,
    },
    Respond {
        status: u16,
        #[serde(default, deserialize_with = "present")]
        headers: Option<Vec<HeaderField>>,
        #[serde(default, deserialize_with = "present")]
        body: Option<BodyOutput>,
    },
    Abort {},
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP script result")
}
fn exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "HTTP script body workspace exceeded",
    )
}

pub(crate) fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

impl Message {
    pub(crate) fn request(
        original: OriginalSnapshot,
        mut request: RequestSnapshot,
        body: Option<Entity>,
        wire_headers: &Fields,
        crossed_origin: bool,
    ) -> Self {
        update_host(&mut request.headers, &request.url);
        Self {
            original,
            request,
            response: None,
            body,
            crossed_origin,
            protected: nominated(wire_headers),
            partial_response: false,
            conditions: (0, 0),
        }
    }

    pub(crate) fn response(
        original: OriginalSnapshot,
        mut request: RequestSnapshot,
        response: ResponseSnapshot,
        body: Option<Entity>,
        wire_headers: &Fields,
    ) -> Self {
        let partial_response = response.status == 206
            || wire_headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-range"));
        update_host(&mut request.headers, &request.url);
        Self {
            original,
            request,
            response: Some(response),
            body,
            crossed_origin: false,
            protected: nominated(wire_headers),
            partial_response,
            conditions: (0, 0),
        }
    }

    pub(crate) fn with_conditions(mut self, request: u64, response: u64) -> Self {
        self.conditions = (request, response);
        self
    }

    fn selection(&self) -> RequestMatch<'_> {
        RequestMatch::from((&self.original.url, self.original.method.as_str()))
            .with_conditions(self.conditions.0, self.conditions.1)
    }

    pub(crate) fn phase(&self) -> Phase {
        if self.response.is_some() {
            Phase::Response
        } else {
            Phase::Request
        }
    }

    fn fields(&self) -> &Fields {
        self.response
            .as_ref()
            .map_or(&self.request.headers, |r| &r.headers)
    }

    fn metadata(&self, mode: BodyMode) -> io::Result<Value> {
        headers::check(&self.request.headers)?;
        headers::check(self.fields())?;
        let snapshot = |fields: &Fields| -> Value {
            fields
                .iter()
                .map(|(name, value)| json!({"name":name.to_ascii_lowercase(),"value":value}))
                .collect()
        };
        let mut input = json!({
            "phase": if self.phase() == Phase::Request { "request" } else { "response" },
            "original": {"url":self.original.url.as_str(),"method":self.original.method},
            "request": {"url":self.request.url.as_str(),"method":self.request.method,
                "headers":null},
            "body": {"kind":match mode { BodyMode::None=>"not-requested",BodyMode::Text=>"text",BodyMode::Bytes=>"bytes"}},
        });
        *input
            .get_mut("request")
            .and_then(|request| request.get_mut("headers"))
            .expect("request header slot is constructed above") = snapshot(&self.request.headers);
        if let Some(response) = &self.response {
            input["response"] = json!({"status":response.status,"headers":null});
            *input
                .get_mut("response")
                .and_then(|response| response.get_mut("headers"))
                .expect("response header slot is constructed above") = snapshot(&response.headers);
        }
        Ok(input)
    }

    fn check_header(&self, name: &str) -> io::Result<()> {
        rules::validate_header_name(name)?;
        if self.protected.contains(&name.to_ascii_lowercase())
            || matches!(
                name.to_ascii_lowercase().as_str(),
                "proxy-authorization" | "proxy-authenticate" | "content-range"
            )
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Validation and representation repair happen before replacing any input.
    #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
    pub(crate) fn apply(
        &mut self,
        output: ScriptOutput,
        output_body: BudgetedBytes,
        mode: BodyMode,
    ) -> io::Result<Outcome> {
        self.apply_checked(output, output_body, mode, |_, _| true)
    }

    fn apply_checked(
        &mut self,
        output: ScriptOutput,
        output_body: BudgetedBytes,
        mode: BodyMode,
        allows_upstream: impl FnOnce(&Url, &Url) -> bool,
    ) -> io::Result<Outcome> {
        match output {
            ScriptOutput::Pass {} => {
                if !output_body.as_ref().is_empty() {
                    return Err(invalid());
                }
                Ok(Outcome::Forward)
            }
            ScriptOutput::Abort {} => {
                if !output_body.as_ref().is_empty() {
                    return Err(invalid());
                }
                Ok(Outcome::Abort)
            }
            ScriptOutput::Modify {
                url,
                method,
                status,
                headers: operations,
                body: result_body,
            } => {
                let request_phase = self.response.is_none();
                if (request_phase && status.is_some())
                    || (!request_phase && (url.is_some() || method.is_some()))
                {
                    return Err(invalid());
                }
                if request_phase
                    && self.original.asterisk
                    && (url.is_some() || method.is_some() || result_body.is_some())
                {
                    return Err(invalid());
                }
                let next_url = url.as_deref().map(rules::checked_url).transpose()?;
                if let Some(url) = &next_url
                    && !allows_upstream(&self.request.url, url)
                {
                    return Err(invalid());
                }
                let origin_changed = next_url
                    .as_ref()
                    .is_some_and(|url| !same_origin(&self.request.url, url));
                if let Some(method) = &method {
                    http::Method::from_bytes(method.as_bytes()).map_err(|_| invalid())?;
                    if method.len() > headers::MAX_BYTES
                        || (method != &self.request.method
                            && (matches!(method.as_str(), "HEAD" | "CONNECT")
                                || matches!(self.request.method.as_str(), "HEAD" | "CONNECT")))
                    {
                        return Err(invalid());
                    }
                }
                if let Some(status) = status {
                    let old = self.response.as_ref().ok_or_else(invalid)?.status;
                    if !(200..=599).contains(&status)
                        || (status != old
                            && (self.partial_response
                                || special_status(old)
                                || special_status(status)))
                    {
                        return Err(invalid());
                    }
                }
                let mut fields = self.fields().clone();
                if origin_changed {
                    headers::strip_origin_credentials(&mut fields);
                }
                if let Some(url) = &next_url {
                    update_host(&mut fields, url);
                }
                if let Some(operations) = operations {
                    self.apply_headers(&mut fields, operations)?;
                }
                let mut replacement = None;
                if let Some(body) = result_body {
                    if mode == BodyMode::None {
                        return Err(invalid());
                    }
                    let baseline = self
                        .body
                        .as_ref()
                        .and_then(Entity::logical)
                        .ok_or_else(invalid)?;
                    validate_body(&output_body, body.kind)?;
                    if output_body.as_ref() != baseline {
                        body::repair_metadata_kind(
                            &mut fields,
                            output_body.as_ref().len(),
                            body.kind == BodyKind::Text,
                        );
                        replacement = Some(output_body);
                    }
                } else if !output_body.as_ref().is_empty() {
                    return Err(invalid());
                }
                headers::check(&fields)?;
                // This is the first commit. Every validation above is complete;
                // rejecting a foreign owner leaves body and metadata intact.
                if let Some(bytes) = replacement {
                    self.body
                        .as_mut()
                        .expect("validated body input")
                        .replace(bytes)
                        .map_err(|_| invalid())?;
                }
                if let Some(response) = &mut self.response {
                    response.headers = fields;
                    if let Some(status) = status {
                        response.status = status;
                    }
                } else {
                    self.request.headers = fields;
                    if let Some(url) = next_url {
                        self.request.url = url;
                    }
                    if let Some(method) = method {
                        self.request.method = method;
                    }
                    self.crossed_origin |= origin_changed;
                }
                Ok(Outcome::Forward)
            }
            ScriptOutput::Respond {
                status,
                headers: initial,
                body: result_body,
            } => {
                if !(200..=599).contains(&status) || status == 206 {
                    return Err(invalid());
                }
                let mut fields = Vec::new();
                for field in initial.unwrap_or_default() {
                    self.check_header(&field.name)?;
                    rules::validate_header_value(&field.value)?;
                    fields.push((field.name.to_ascii_lowercase(), field.value));
                }
                headers::check(&fields)?;
                let length = output_body.as_ref().len();
                if result_body.is_none() && length != 0 {
                    return Err(invalid());
                }
                if let Some(body) = &result_body {
                    validate_body(&output_body, body.kind)?;
                }
                let no_body = self.original.method == "HEAD" || matches!(status, 204 | 205 | 304);
                if length != 0 && (no_body || !self.original.identity_allowed) {
                    return Err(invalid());
                }
                if result_body
                    .as_ref()
                    .is_some_and(|body| body.kind == BodyKind::Text)
                {
                    repair_charset(&mut fields);
                }
                if !no_body || (status == 205 && self.original.method != "HEAD") {
                    fields.push(("content-length".into(), length.to_string()));
                }
                headers::check(&fields)?;
                let body = if result_body.is_some() && length != 0 {
                    output_body.into_bytes()
                } else {
                    Bytes::new()
                };
                Ok(Outcome::Respond(LocalResponse {
                    status,
                    headers: fields,
                    body,
                }))
            }
        }
    }

    fn apply_headers(&self, fields: &mut Fields, operations: Vec<HeaderOp>) -> io::Result<()> {
        if operations.len() > headers::MAX_FIELDS {
            return Err(invalid());
        }
        let mut records = 0usize;
        let mut values_total = 0usize;
        for operation in operations {
            let (name, values, set) = match operation {
                HeaderOp::Set { name, values } => (name, Some(values), true),
                HeaderOp::Add { name, values } => (name, Some(values), false),
                HeaderOp::Remove { name } => (name, None, true),
            };
            self.check_header(&name)?;
            let name = name.to_ascii_lowercase();
            if set {
                fields.retain(|(old, _)| !old.eq_ignore_ascii_case(&name));
            }
            if let Some(values) = values {
                if values.is_empty() {
                    return Err(invalid());
                }
                values_total = values_total.checked_add(values.len()).ok_or_else(invalid)?;
                if values_total > headers::MAX_FIELDS {
                    return Err(invalid());
                }
                for value in values {
                    rules::validate_header_value(&value)?;
                    records = records
                        .checked_add(name.len() + value.len() + 32)
                        .ok_or_else(invalid)?;
                    if records > headers::MAX_BYTES {
                        return Err(invalid());
                    }
                    fields.push((name.clone(), value));
                }
            } else {
                records = records.checked_add(name.len() + 32).ok_or_else(invalid)?;
                if records > headers::MAX_BYTES {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

fn special_status(status: u16) -> bool {
    matches!(status, 204 | 205 | 304 | 206)
}
fn update_host(fields: &mut Fields, url: &Url) {
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("host") {
            *value = url[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
        }
    }
}
fn nominated(fields: &Fields) -> BTreeSet<String> {
    fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect()
}
fn validate_body(body: &BudgetedBytes, kind: BodyKind) -> io::Result<()> {
    if body.as_ref().len() > MAX_BODY
        || (kind == BodyKind::Text && std::str::from_utf8(body.as_ref()).is_err())
    {
        return Err(invalid());
    }
    Ok(())
}
fn repair_charset(fields: &mut Fields) {
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("content-type") {
            let mut pieces = value.split(';');
            let mut result = pieces.next().unwrap_or_default().to_owned();
            for piece in pieces {
                if piece
                    .split_once('=')
                    .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("charset"))
                {
                    continue;
                }
                result.push(';');
                result.push_str(piece);
            }
            result.push_str("; charset=utf-8");
            *value = result;
        }
    }
}
fn readable_text(fields: &Fields, bytes: &[u8]) -> bool {
    if std::str::from_utf8(bytes).is_err() {
        return false;
    }
    let mut content_types = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    let Some((_, value)) = content_types.next() else {
        return true;
    };
    if content_types.next().is_some() {
        return false;
    }
    value.split(';').skip(1).all(|piece| {
        !piece.split_once('=').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("charset")
                && !matches!(
                    value.trim().trim_matches('"').to_ascii_lowercase().as_str(),
                    "utf-8" | "utf8"
                )
        })
    })
}

// Preserve the existing per-invocation output-owner charge while queued;
// only its not-yet-allocated payload is deferred until the same lane is held.
#[cfg(target_vendor = "apple")]
struct PendingPlanOutput<'a> {
    budget: &'a Budget,
    reservation: super::body_budget::Reservation,
    bound: usize,
}
#[cfg(target_vendor = "apple")]
const _: () = assert!(
    std::mem::size_of::<PendingPlanOutput<'static>>() <= std::mem::size_of::<BudgetedBytes>()
);
#[cfg(target_vendor = "apple")]
impl<'a> PendingPlanOutput<'a> {
    fn new(
        budget: &'a Budget,
        bytes: Option<&[u8]>,
        mode: BodyMode,
        backend: super::scripts::Backend<'_>,
    ) -> io::Result<Self> {
        let bound = backend.output_bound(bytes.map_or(0, <[u8]>::len));
        if !backend.is_plan()
            || mode != BodyMode::Text
            || bytes.is_none_or(|bytes| bytes.len() > MAX_BODY)
            || bound > MAX_BODY
        {
            return Err(invalid());
        }
        let output_cost = BudgetedBytes::allocation_cost(bound).ok_or_else(exhausted)?;
        let bookkeeping = BudgetedBytes::allocation_cost(0).ok_or_else(exhausted)?;
        super::diagnostics::call_buffers_requested(0, output_cost, 0);
        let reservation = budget.reserve(bookkeeping).ok_or_else(|| {
            super::diagnostics::increment(super::diagnostics::Counter::CallBuffersBudgetRejected);
            exhausted()
        })?;
        super::diagnostics::increment(super::diagnostics::Counter::PlanOutputPendingAdmitted);
        Ok(Self {
            budget,
            reservation,
            bound,
        })
    }
    // The caller already owns InvocationLane. No wait and no second queue.
    fn materialize(mut self) -> io::Result<CallBuffers> {
        let payload = self.budget.reserve(self.bound).ok_or_else(|| {
            super::diagnostics::increment(
                super::diagnostics::Counter::PlanOutputPayloadBudgetRejected,
            );
            super::diagnostics::increment(super::diagnostics::Counter::CallBuffersBudgetRejected);
            exhausted()
        })?;
        self.reservation.merge(payload).map_err(|_| invalid())?;
        let output = BudgetedBytes::from_reserved_fixed_output(self.reservation, self.bound)
            .ok_or_else(|| {
                super::diagnostics::increment(
                    super::diagnostics::Counter::CallBuffersAllocationRejected,
                );
                exhausted()
            })?;
        super::diagnostics::increment(super::diagnostics::Counter::CallBuffersAdmitted);
        Ok(CallBuffers {
            output,
            bridge_workspace: None,
        })
    }
}

struct CallBuffers {
    output: BudgetedBytes,
    bridge_workspace: Option<super::body_budget::Reservation>,
}
impl CallBuffers {
    fn for_backend(
        budget: &Budget,
        bytes: Option<&[u8]>,
        mode: BodyMode,
        backend: super::scripts::Backend<'_>,
    ) -> io::Result<Self> {
        let bound = backend.output_bound(bytes.map_or(0, <[u8]>::len));
        if !backend.is_plan() {
            return Self::with_output_bound(budget, bytes, mode, bound);
        }
        // Selection is final: a refusal skips this invocation, never JSC.
        if mode != BodyMode::Text
            || bytes.is_none_or(|bytes| bytes.len() > MAX_BODY)
            || bound > MAX_BODY
        {
            return Err(invalid());
        }
        let output_cost = BudgetedBytes::allocation_cost(bound).ok_or_else(exhausted)?;
        super::diagnostics::call_buffers_requested(0, output_cost, 0);
        let permit = budget.reserve(output_cost).ok_or_else(|| {
            super::diagnostics::increment(super::diagnostics::Counter::CallBuffersBudgetRejected);
            exhausted()
        })?;
        let output = BudgetedBytes::from_reserved(permit, bound).ok_or_else(|| {
            super::diagnostics::increment(
                super::diagnostics::Counter::CallBuffersAllocationRejected,
            );
            exhausted()
        })?;
        super::diagnostics::increment(super::diagnostics::Counter::CallBuffersAdmitted);
        Ok(Self {
            output,
            bridge_workspace: None,
        })
    }
    fn with_output_bound(
        budget: &Budget,
        bytes: Option<&[u8]>,
        mode: BodyMode,
        output_bound: usize,
    ) -> io::Result<Self> {
        let bridge_cost = super::scripts::bridge_cost(
            bytes.map(<[u8]>::len),
            mode == BodyMode::Text,
            output_bound,
        )
        .ok_or_else(exhausted)?;
        let Some(bytes) = bytes else {
            super::diagnostics::call_buffers_requested(0, 0, bridge_cost);
            let bridge_workspace = if bridge_cost == 0 {
                None
            } else {
                Some(budget.reserve(bridge_cost).ok_or_else(|| {
                    super::diagnostics::increment(
                        super::diagnostics::Counter::CallBuffersBudgetRejected,
                    );
                    exhausted()
                })?)
            };
            super::diagnostics::increment(super::diagnostics::Counter::CallBuffersAdmitted);
            return Ok(Self {
                output: BudgetedBytes::empty(budget),
                bridge_workspace,
            });
        };
        if bytes.len() > MAX_BODY || output_bound > MAX_BODY {
            return Err(invalid());
        }
        // The immutable Entity remains borrowed through the real owner join.
        // JSC still creates its independently paid string/typed-array copy.
        // One prepaid terminator byte preserves the ASCII public export API.
        // Actual result bytes remain limited by output_bound in the adapter.
        let output_capacity =
            super::body_budget::output_capacity(output_bound).ok_or_else(exhausted)?;
        let output_cost = BudgetedBytes::allocation_cost(output_capacity).ok_or_else(exhausted)?;
        super::diagnostics::call_buffers_requested(0, output_cost, bridge_cost);
        let mut all = budget
            .reserve(output_cost.checked_add(bridge_cost).ok_or_else(exhausted)?)
            .ok_or_else(|| {
                super::diagnostics::increment(
                    super::diagnostics::Counter::CallBuffersBudgetRejected,
                );
                exhausted()
            })?;
        let bridge_workspace = Some(all.split(bridge_cost).ok_or_else(exhausted)?);
        let allocation_failed = || {
            super::diagnostics::increment(
                super::diagnostics::Counter::CallBuffersAllocationRejected,
            );
            exhausted()
        };
        let output =
            BudgetedBytes::from_reserved(all, output_capacity).ok_or_else(allocation_failed)?;
        super::diagnostics::increment(super::diagnostics::Counter::CallBuffersAdmitted);
        Ok(Self {
            output,
            bridge_workspace,
        })
    }
}

fn script_metadata(message: &Message, script: &CompiledScript) -> io::Result<Value> {
    let mut metadata = message.metadata(script.body)?;
    if !script.parameters.is_empty() {
        metadata["parameters"] =
            serde_json::to_value(script.parameters.as_ref()).map_err(|_| invalid())?;
    }
    Ok(metadata)
}

pub(crate) async fn run(
    policy: &Policy,
    original: &Url,
    message: &mut Message,
    cancellation: &CancellationToken,
) -> io::Result<Outcome> {
    run_until(
        policy,
        original,
        message,
        cancellation,
        Instant::now() + Duration::from_secs(1),
    )
    .await
}

type ScriptObserver<'a> =
    dyn FnMut(&CompiledScript, &'static str, Option<&'static str>) + Send + 'a;

#[cfg(feature = "invoke")]
pub(crate) async fn run_observed(
    policy: &Policy,
    message: &mut Message,
    cancellation: &CancellationToken,
    observe: &mut ScriptObserver<'_>,
) -> io::Result<Outcome> {
    let original = message.original.url.clone();
    run_until_observed(
        policy,
        &original,
        message,
        cancellation,
        Instant::now() + Duration::from_secs(1),
        Some(observe),
    )
    .await
}

fn report_backend_error(error: io::Error, script_name: &str, phase: Phase) -> io::Result<()> {
    if matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::Unsupported
    ) {
        super::diagnostics::increment(super::diagnostics::Counter::BackendFatal);
        tracing::warn!(target: "vole::http_processing::script", script = %script_name, phase = ?phase, error_kind = ?error.kind(), error = %error, "HTTP script backend failed");
        Err(error)
    } else {
        tracing::warn!(target: "vole::http_processing::script", script = %script_name, phase = ?phase, error_kind = ?error.kind(), error = %error, "HTTP script failed");
        Ok(())
    }
}

fn check_stage(cancellation: &CancellationToken, deadline: Instant) -> io::Result<()> {
    if cancellation.is_cancelled() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

async fn run_until(
    policy: &Policy,
    original: &Url,
    message: &mut Message,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> io::Result<Outcome> {
    run_until_observed(policy, original, message, cancellation, deadline, None).await
}

async fn run_until_observed(
    policy: &Policy,
    original: &Url,
    message: &mut Message,
    cancellation: &CancellationToken,
    deadline: Instant,
    mut observe: Option<&mut ScriptObserver<'_>>,
) -> io::Result<Outcome> {
    let mut record = |script: &CompiledScript, outcome, reason| {
        if let Some(observe) = &mut observe {
            observe(script, outcome, reason);
        }
    };
    if &message.original.url != original {
        return Err(invalid());
    }
    check_stage(cancellation, deadline)?;
    let phase = message.phase();
    for script in policy
        .scripts()
        .iter()
        .filter(|script| script.phase == phase)
    {
        if !script.matches(message.selection()) {
            continue;
        }
        check_stage(cancellation, deadline)?;
        super::diagnostics::increment(super::diagnostics::Counter::ScriptMatched);
        if message.phase() == Phase::Request
            && message.original.asterisk
            && script.body != BodyMode::None
        {
            super::diagnostics::increment(super::diagnostics::Counter::SkipAsteriskBody);
            record(script, "skipped", Some("asterisk-body"));
            tracing::debug!(target: "vole::http_processing::script", script = %script.name, phase = ?phase, reason = "asterisk-body", "HTTP script skipped");
            continue;
        }
        let bytes = if script.body == BodyMode::None {
            None
        } else {
            let Some(bytes) = message.body.as_ref().and_then(Entity::logical) else {
                super::diagnostics::increment(super::diagnostics::Counter::SkipBodyUnavailable);
                record(script, "skipped", Some("body-unavailable"));
                tracing::debug!(target: "vole::http_processing::script", script = %script.name, phase = ?phase, reason = "body-unavailable", "HTTP script skipped");
                continue;
            };
            let text_readable = message.body.as_ref().is_some_and(|body| {
                if body.changed() {
                    readable_text(message.fields(), bytes)
                } else {
                    body.original_text_allowed() && std::str::from_utf8(bytes).is_ok()
                }
            });
            if script.body == BodyMode::Text && !text_readable {
                super::diagnostics::increment(super::diagnostics::Counter::SkipTextUnavailable);
                record(script, "skipped", Some("text-unavailable"));
                tracing::debug!(target: "vole::http_processing::script", script = %script.name, phase = ?phase, reason = "text-unavailable", "HTTP script skipped");
                continue;
            }
            Some(bytes)
        };
        #[cfg(not(target_vendor = "apple"))]
        let acquired_lane = if script.body == BodyMode::Bytes
            && cfg!(any(
                all(target_os = "android", feature = "ffi"),
                all(target_os = "linux", feature = "http-js-quickjs")
            )) {
            // Queue with the already collected input. Only an active
            // invocation needs a metadata snapshot, output and bridge copies.
            match super::scripts::InvocationLane::acquire_engine(cancellation, deadline).await {
                Ok(lane) => Some(lane),
                Err(error) => {
                    check_stage(cancellation, deadline)?;
                    let failure = report_backend_error(error, &script.name, phase);
                    if failure.is_err() {
                        record(script, "failed", Some("backend-fatal"));
                    } else {
                        record(script, "rolled-back", Some("invocation-timeout"));
                    }
                    failure?;
                    continue;
                }
            }
        } else {
            None
        };
        let parameter_work = script.parameter_work_bytes();
        let _parameters_owner = if parameter_work == 0 {
            None
        } else if let Some(owner) = policy.body_budget().reserve(parameter_work) {
            Some(owner)
        } else {
            super::diagnostics::increment(super::diagnostics::Counter::SkipCallBuffers);
            record(script, "skipped", Some("body-budget"));
            continue;
        };
        let Ok(metadata) = script_metadata(message, script) else {
            super::diagnostics::increment(super::diagnostics::Counter::SkipInputUnrepresentable);
            record(script, "skipped", Some("input-unrepresentable"));
            tracing::debug!(target: "vole::http_processing::script", script = %script.name, phase = ?phase, reason = "input-unrepresentable", "HTTP script skipped");
            continue;
        };
        // Both references borrow the same immutable Entity owner. The witness
        // adds ledger identity, never another input copy or reservation.
        let borrowed = bytes.and_then(|_| message.body.as_ref().and_then(Entity::borrowed_body));
        let backend = script.compiled.backend(&metadata, borrowed);
        #[cfg(target_vendor = "apple")]
        let mut acquired_lane = None;
        let prepared_buffers = {
            #[cfg(target_vendor = "apple")]
            if backend.is_plan() {
                match PendingPlanOutput::new(policy.body_budget(), bytes, script.body, backend) {
                    Err(error) => Err(error),
                    Ok(pending) => {
                        let lane =
                            match super::scripts::InvocationLane::acquire(cancellation, deadline)
                                .await
                            {
                                Ok(lane) => lane,
                                Err(error) => {
                                    super::diagnostics::increment(
                                        super::diagnostics::Counter::PlanOutputQueueFailed,
                                    );
                                    check_stage(cancellation, deadline)?;
                                    let failure = report_backend_error(error, &script.name, phase);
                                    if failure.is_err() {
                                        record(script, "failed", Some("backend-fatal"));
                                    } else {
                                        record(script, "rolled-back", Some("invocation-timeout"));
                                    }
                                    failure?;
                                    continue;
                                }
                            };
                        acquired_lane = Some(lane);
                        pending.materialize()
                    }
                }
            } else {
                CallBuffers::for_backend(policy.body_budget(), bytes, script.body, backend)
            }
            #[cfg(not(target_vendor = "apple"))]
            {
                CallBuffers::for_backend(policy.body_budget(), bytes, script.body, backend)
            }
        };
        let Ok(mut buffers) = prepared_buffers else {
            if backend.is_plan() {
                super::diagnostics::increment(super::diagnostics::Counter::PlanBuffersRejected);
            }
            super::diagnostics::increment(super::diagnostics::Counter::SkipCallBuffers);
            record(script, "skipped", Some("body-budget"));
            tracing::debug!(target: "vole::http_processing::script", script = %script.name, phase = ?phase, reason = "body-budget", "HTTP script skipped");
            continue;
        };
        let result = {
            #[cfg(target_vendor = "apple")]
            if let Some(lane) = acquired_lane {
                if super::scripts::plan_can_run_direct() {
                    // Keep this exact paid output and acquired lane/deadline.
                    // One scheduling opportunity, not an IO-poll guarantee.
                    tokio::task::yield_now().await;
                }
                super::scripts::evaluate_plan_in_lane(
                    backend,
                    &metadata,
                    borrowed,
                    &mut buffers.output,
                    cancellation,
                    lane,
                )
            } else {
                super::scripts::evaluate_backend_until(
                    backend,
                    &metadata,
                    // The typed witness borrows the actual sender-owned Bytes, through
                    // the same actual backend owner/TLS join. No raw slice retagging.
                    borrowed,
                    &mut buffers.output,
                    buffers.bridge_workspace.as_ref(),
                    cancellation,
                    deadline,
                )
                .await
            }
            #[cfg(not(target_vendor = "apple"))]
            if let Some(lane) = &acquired_lane {
                super::scripts::evaluate_engine_in_lane(
                    backend,
                    &metadata,
                    bytes,
                    &mut buffers.output,
                    buffers.bridge_workspace.as_ref(),
                    cancellation,
                    lane,
                )
            } else {
                super::scripts::evaluate_backend_until(
                    backend,
                    &metadata,
                    // The typed witness borrows the actual sender-owned Bytes, through
                    // the same actual backend owner/TLS join. No raw slice retagging.
                    borrowed,
                    &mut buffers.output,
                    buffers.bridge_workspace.as_ref(),
                    cancellation,
                    deadline,
                )
                .await
            }
        };
        drop(buffers.bridge_workspace.take());
        #[cfg(not(target_vendor = "apple"))]
        drop(acquired_lane);
        check_stage(cancellation, deadline)?;
        let metadata = match result {
            Ok(metadata) => metadata,
            Err(error) => {
                let reason = if error.kind() == io::ErrorKind::TimedOut {
                    "invocation-timeout"
                } else {
                    "execution-error"
                };
                let failure = report_backend_error(error, &script.name, phase);
                if failure.is_err() {
                    record(script, "failed", Some("backend-fatal"));
                } else {
                    record(script, "rolled-back", Some(reason));
                }
                failure?;
                continue;
            }
        };
        let mut accepted = "accepted";
        let result = serde_json::from_value::<ScriptOutput>(metadata)
            .map_err(|_| invalid())
            .and_then(|output| {
                if matches!(&output, ScriptOutput::Pass {}) {
                    accepted = "passed";
                }
                message.apply_checked(
                    output,
                    buffers.output,
                    script.body,
                    |previous, candidate| script.allows_upstream(previous, candidate),
                )
            });
        check_stage(cancellation, deadline)?;
        match result {
            Ok(Outcome::Forward) => {
                super::diagnostics::increment(super::diagnostics::Counter::OutputAccepted);
                record(script, accepted, None);
            }
            Ok(terminal) => {
                super::diagnostics::increment(super::diagnostics::Counter::OutputTerminal);
                record(
                    script,
                    if matches!(&terminal, Outcome::Abort) {
                        "abort"
                    } else {
                        "respond"
                    },
                    None,
                );
                return Ok(terminal);
            }
            Err(error) => {
                super::diagnostics::increment(super::diagnostics::Counter::OutputRejected);
                record(script, "rolled-back", Some("invalid-result"));
                tracing::warn!(target: "vole::http_processing::script", script = %script.name, phase = ?phase, error_kind = ?error.kind(), error = %error, "HTTP script result rejected")
            }
        }
    }
    check_stage(cancellation, deadline)?;
    Ok(Outcome::Forward)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_local_reply_keeps_queued_bytes_charged_and_omits_head_entities() {
        let budget = Budget::default();
        let response = StaticResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: Bytes::from_static(b"local"),
        };
        let head = LocalResponse::from_static(&response, true, false, &budget);
        assert_eq!(head.status, 200);
        assert_eq!(head.headers, response.headers);
        assert!(head.body.is_empty());
        assert_eq!(budget.used(), 0);
        for (status, fields) in [
            (204, vec![]),
            (205, vec![("content-length".to_owned(), "0".to_owned())]),
            (304, vec![]),
        ] {
            let configured = StaticResponse {
                status,
                headers: vec![],
                body: Bytes::new(),
            };
            let reply = LocalResponse::from_static(&configured, false, false, &budget);
            assert_eq!(reply.status, status);
            assert_eq!(reply.headers, fields);
            assert!(reply.body.is_empty());
        }
        let rejected = LocalResponse::from_static(&response, false, false, &budget);
        assert_eq!(rejected.status, 406);
        assert!(rejected.body.is_empty());

        let reply = LocalResponse::from_static(&response, false, true, &budget);
        let chunk = reply.body.slice(1..);
        assert_eq!(budget.used(), 5);
        drop(reply);
        assert_eq!(budget.used(), 5);
        assert_eq!(chunk.as_ref(), b"ocal");
        drop(chunk);
        assert_eq!(budget.used(), 0);

        let full = budget
            .reserve(super::super::body_budget::WORKSPACE)
            .unwrap();
        let unavailable = LocalResponse::from_static(&response, false, true, &budget);
        assert_eq!(unavailable.status, 503);
        assert!(unavailable.body.is_empty());
        drop(full);
        assert_eq!(budget.used(), 0);
    }

    fn request(budget: &Budget) -> Message {
        let url = Url::parse("https://a.example/path").unwrap();
        let fields = vec![
            ("Authorization".into(), "old-secret".into()),
            ("Cookie".into(), "a=1".into()),
        ];
        Message::request(
            OriginalSnapshot {
                url: url.clone(),
                method: "GET".into(),
                identity_allowed: true,
                asterisk: false,
            },
            RequestSnapshot {
                url,
                method: "GET".into(),
                headers: fields.clone(),
            },
            Some(Entity::identity(
                BudgetedBytes::copy(budget, b"original").unwrap(),
            )),
            &fields,
            false,
        )
    }
    fn output(value: Value) -> ScriptOutput {
        serde_json::from_value(value).unwrap()
    }
    fn apply(
        message: &mut Message,
        budget: &Budget,
        value: Value,
        bytes: &[u8],
        mode: BodyMode,
    ) -> io::Result<Outcome> {
        message.apply(
            output(value),
            BudgetedBytes::copy(budget, bytes).unwrap(),
            mode,
        )
    }

    #[test]
    fn candidate_failure_preserves_url_credentials_body_and_prior_success() {
        let budget = Budget::default();
        let mut message = request(&budget);
        apply(&mut message, &budget, json!({"type":"modify","headers":[{"op":"add","name":"x-first","values":["accepted"]}]}), b"", BodyMode::None).unwrap();
        assert!(apply(&mut message, &budget, json!({"type":"modify","url":"https://b.example/","headers":[{"op":"set","name":"x-bad","values":["bad\r\nvalue"]}],"body":{"kind":"text"}}), b"changed", BodyMode::Text).is_err());
        assert_eq!(message.request.url.host_str(), Some("a.example"));
        assert_eq!(
            message.body.as_ref().unwrap().logical().unwrap(),
            b"original"
        );
        assert!(
            message
                .request
                .headers
                .iter()
                .any(|(n, v)| n == "Authorization" && v == "old-secret")
        );
        assert!(
            message
                .request
                .headers
                .iter()
                .any(|(n, v)| n == "x-first" && v == "accepted")
        );
        assert!(!message.crossed_origin);
        drop(message);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn each_origin_transition_cleans_inherited_values_but_accepts_explicit_values() {
        let budget = Budget::default();
        let mut message = request(&budget);
        apply(&mut message,&budget,json!({"type":"modify","url":"https://b.example/","headers":[{"op":"set","name":"authorization","values":["b-secret"]}]}),b"",BodyMode::None).unwrap();
        assert_eq!(
            message.request.headers,
            vec![("authorization".into(), "b-secret".into())]
        );
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","url":"https://a.example/"}),
            b"",
            BodyMode::None,
        )
        .unwrap();
        assert!(message.request.headers.is_empty());
        assert!(message.crossed_origin);
        apply(&mut message,&budget,json!({"type":"modify","url":"https://a.example:443/new","headers":[{"op":"add","name":"cookie","values":["a=new"]}]}),b"",BodyMode::None).unwrap();
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","url":"https://a.example/path"}),
            b"",
            BodyMode::None,
        )
        .unwrap();
        assert_eq!(
            message.request.headers,
            vec![("cookie".into(), "a=new".into())]
        );
    }

    #[test]
    fn repeated_header_values_and_control_record_limits_are_distinct() {
        let budget = Budget::default();
        let mut message = request(&budget);
        apply(&mut message,&budget,json!({"type":"modify","headers":[{"op":"set","name":"x-values","values":["1","2"]},{"op":"add","name":"X-Values","values":["3"]}]}),b"",BodyMode::None).unwrap();
        let values: Vec<_> = message
            .request
            .headers
            .iter()
            .filter(|(n, _)| n == "x-values")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(values, ["1", "2", "3"]);
        let operations: Vec<_> = (0..101)
            .map(|_| json!({"op":"set","name":"x-values","values":["one"]}))
            .collect();
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","headers":operations}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
        assert_eq!(
            message
                .request
                .headers
                .iter()
                .filter(|(n, _)| n == "x-values")
                .count(),
            3
        );
    }

    #[test]
    fn protected_and_connection_nominated_fields_never_become_writable() {
        let budget = Budget::default();
        let mut message = request(&budget);
        message.protected = nominated(&vec![("Connection".into(), "X-Hop".into())]);
        for name in [
            "Host",
            "content-length",
            "Proxy-Authorization",
            "content-range",
            "X-Hop",
        ] {
            assert!(
                apply(
                    &mut message,
                    &budget,
                    json!({"type":"modify","headers":[{"op":"remove","name":name}]}),
                    b"",
                    BodyMode::None
                )
                .is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn request_host_snapshot_tracks_current_url_and_response_sees_final_request() {
        let budget = Budget::default();
        let mut message = request(&budget);
        message
            .request
            .headers
            .push(("Host".into(), "a.example".into()));
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","url":"https://b.example:8443/final"}),
            b"",
            BodyMode::None,
        )
        .unwrap();
        assert!(
            message
                .request
                .headers
                .iter()
                .any(|(name, value)| name == "Host" && value == "b.example:8443")
        );
        let mut response = Message::response(
            message.original.clone(),
            message.request.clone(),
            ResponseSnapshot {
                status: 200,
                headers: vec![],
            },
            None,
            &vec![],
        );
        let input = response.metadata(BodyMode::None).unwrap();
        assert_eq!(input["original"]["url"], "https://a.example/path");
        assert_eq!(input["request"]["url"], "https://b.example:8443/final");
        assert_eq!(
            input["request"]["headers"],
            json!([{"name":"host","value":"b.example:8443"}])
        );
        assert_eq!(input["body"], json!({"kind":"not-requested"}));
        assert!(
            apply(
                &mut response,
                &budget,
                json!({"type":"modify","url":"https://a.example/"}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
        assert_eq!(
            response.request.url.as_str(),
            "https://b.example:8443/final"
        );
    }

    #[test]
    fn method_status_and_phase_rules_cannot_change_http_message_classes() {
        let budget = Budget::default();
        let mut message = request(&budget);
        for method in ["HEAD", "CONNECT", "bad method", ""] {
            assert!(
                apply(
                    &mut message,
                    &budget,
                    json!({"type":"modify","method":method}),
                    b"",
                    BodyMode::None
                )
                .is_err()
            );
        }
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","method":"PATCH"}),
            b"",
            BodyMode::None,
        )
        .unwrap();
        assert_eq!(message.request.method, "PATCH");
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","status":201}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
        message.response = Some(ResponseSnapshot {
            status: 200,
            headers: vec![],
        });
        for status in [101, 204, 205, 206, 304, 600] {
            assert!(
                apply(
                    &mut message,
                    &budget,
                    json!({"type":"modify","status":status}),
                    b"",
                    BodyMode::None
                )
                .is_err()
            );
        }
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","status":201}),
            b"",
            BodyMode::None,
        )
        .unwrap();
        message.response.as_mut().unwrap().status = 204;
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","status":304}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","status":204}),
            b"",
            BodyMode::None,
        )
        .unwrap();
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","url":"https://b.example/"}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
    }

    #[test]
    fn local_results_respect_identity_head_status_and_duplicate_cookie_values() {
        let budget = Budget::default();
        let mut message = request(&budget);
        message.original.identity_allowed = false;
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"respond","status":200,"body":{"kind":"bytes"}}),
                b"new",
                BodyMode::None
            )
            .is_err()
        );
        message.original.identity_allowed = true;
        for status in [204, 205, 304, 206] {
            assert!(
                apply(
                    &mut message,
                    &budget,
                    json!({"type":"respond","status":status,"body":{"kind":"text"}}),
                    b"new",
                    BodyMode::None
                )
                .is_err()
            );
        }
        let Outcome::Respond(response)=apply(&mut message,&budget,json!({"type":"respond","status":200,"headers":[{"name":"Set-Cookie","value":"a=1"},{"name":"Set-Cookie","value":"b=2"}],"body":{"kind":"text"}}),b"new",BodyMode::None).unwrap() else { panic!("local response") };
        assert_eq!(response.body, b"new".as_slice());
        assert_eq!(
            response
                .headers
                .iter()
                .filter(|(n, _)| n == "set-cookie")
                .count(),
            2
        );
        message.original.method = "HEAD".into();
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"respond","status":200,"body":{"kind":"bytes"}}),
                b"new",
                BodyMode::None
            )
            .is_err()
        );
        let Outcome::Respond(response) = apply(
            &mut message,
            &budget,
            json!({"type":"respond","status":200}),
            b"",
            BodyMode::None,
        )
        .unwrap() else {
            panic!("local HEAD")
        };
        assert!(!response.headers.iter().any(|(n, _)| n == "content-length"));
    }

    #[test]
    fn binary_repair_does_not_guess_charset_and_metadata_failure_rolls_back() {
        let budget = Budget::default();
        let mut message = request(&budget);
        message.request.headers = vec![
            (
                "content-type".into(),
                "application/octet-stream; charset=latin1".into(),
            ),
            ("etag".into(), "old".into()),
            ("content-encoding".into(), "gzip".into()),
        ];
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","body":{"kind":"bytes"}}),
            &[0xff, 0x00],
            BodyMode::Bytes,
        )
        .unwrap();
        assert!(
            message
                .request
                .headers
                .iter()
                .any(|(n, v)| n == "content-type" && v.ends_with("latin1"))
        );
        assert!(
            !message
                .request
                .headers
                .iter()
                .any(|(n, _)| n == "etag" || n == "content-encoding")
        );
        assert!(!readable_text(
            &message.request.headers,
            message.body.as_ref().unwrap().logical().unwrap()
        ));
        apply(
            &mut message,
            &budget,
            json!({"type":"modify","body":{"kind":"text"}}),
            b"UTF-8",
            BodyMode::Bytes,
        )
        .unwrap();
        assert!(readable_text(
            &message.request.headers,
            message.body.as_ref().unwrap().logical().unwrap()
        ));
        message.request.headers = (0..100)
            .map(|n| (format!("x-{n}"), "value".into()))
            .collect();
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","body":{"kind":"text"}}),
                b"must-rollback",
                BodyMode::Text
            )
            .is_err()
        );
        assert_eq!(message.body.as_ref().unwrap().logical().unwrap(), b"UTF-8");
    }

    #[test]
    fn null_unknown_union_and_body_mode_fail_closed() {
        for value in [
            json!(null),
            json!({"type":"pass","body":{}}),
            json!({"type":"abort","url":"https://example.com/"}),
            json!({"type":"modify","url":null}),
            json!({"type":"modify","body":{"kind":"not-requested"}}),
            json!({"type":"modify","headers":[{"op":"remove","name":"x","values":[]}]}),
            json!({"type":"respond","status":200.5}),
        ] {
            assert!(serde_json::from_value::<ScriptOutput>(value).is_err());
        }
        let budget = Budget::default();
        let mut message = request(&budget);
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","body":{"kind":"bytes"}}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
        message.original.asterisk = true;
        assert!(
            apply(
                &mut message,
                &budget,
                json!({"type":"modify","method":"GET"}),
                b"",
                BodyMode::None
            )
            .is_err()
        );
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test(flavor = "current_thread")]
    async fn bounded_output_arena_production_run_rolls_back_one_call_and_runs_the_next() {
        let policy=Policy::compile(r#"targets:
  - origins: [https://a.example]
    rules:
      - name: reject-protected-header
        match: {path-exact: /path}
        request:
          js:
            body: text
            source: 'function rewrite(input){return {type:"modify",headers:[{op:"set",name:"host",values:["invalid.example"]}],body:{kind:"text",data:"bad"}};}'
      - name: accepted-after-rollback
        match: {path-exact: /path}
        request:
          js:
            body: text
            source: 'function rewrite(input){return {type:"modify",headers:[{op:"add",name:"x-bridge",values:["done"]}],body:{kind:"text",data:input.body.data.replaceAll("i","I")}};}'
"#).unwrap();
        let budget = policy.body_budget();
        let mut message = request(budget);
        let original = message.original.url.clone();
        // Old input/MAX-output/3MAX bridge admission skips both calls here.
        // Bounded copies fit, while total ledger and production lane stay fixed.
        let held = budget
            .reserve(super::super::body_budget::WORKSPACE - budget.used() - 2048)
            .unwrap();
        assert!(matches!(
            run(&policy, &original, &mut message, &CancellationToken::new())
                .await
                .unwrap(),
            Outcome::Forward
        ));
        assert_eq!(
            message.body.as_ref().unwrap().logical().unwrap(),
            b"orIgInal"
        );
        assert!(
            message
                .request
                .headers
                .iter()
                .any(|(name, value)| name == "x-bridge" && value == "done")
        );
        assert!(
            !message
                .request
                .headers
                .iter()
                .any(|(name, value)| name == "host" && value == "invalid.example")
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            matches!(run(&policy,&original,&mut message,&cancelled).await,Err(error) if error.kind()==io::ErrorKind::Interrupted)
        );
        assert_eq!(
            message.body.as_ref().unwrap().logical().unwrap(),
            b"orIgInal"
        );
        drop(held);
        drop(message);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn metadata_only_calls_run_even_when_the_entire_body_workspace_is_held() {
        let budget = Budget::default();
        let url = Url::parse("https://a.example/").unwrap();
        let mut message = Message::request(
            OriginalSnapshot {
                url: url.clone(),
                method: "GET".into(),
                identity_allowed: true,
                asterisk: false,
            },
            RequestSnapshot {
                url,
                method: "GET".into(),
                headers: vec![],
            },
            None,
            &vec![],
            false,
        );
        let held = budget
            .reserve(super::super::body_budget::WORKSPACE)
            .unwrap();
        let buffers = CallBuffers::with_output_bound(&budget, None, BodyMode::None, 0).unwrap();
        message.apply(output(json!({"type":"modify","headers":[{"op":"set","name":"x-meta","values":["yes"]}]})), buffers.output, BodyMode::None).unwrap();
        assert_eq!(
            message.request.headers,
            vec![("x-meta".into(), "yes".into())]
        );
        assert!(
            CallBuffers::with_output_bound(&budget, None, BodyMode::None, 0)
                .unwrap()
                .output
                .prepare_output(1)
                .is_err()
        );
        drop(held);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn generated_205_has_explicit_zero_length_unless_head_semantics_take_precedence() {
        let budget = Budget::default();
        let mut message = request(&budget);
        let Outcome::Respond(response) = apply(
            &mut message,
            &budget,
            json!({"type":"respond","status":205}),
            b"",
            BodyMode::None,
        )
        .unwrap() else {
            panic!("205 response")
        };
        assert_eq!(
            response.headers,
            vec![("content-length".into(), "0".into())]
        );
        message.original.method = "HEAD".into();
        let Outcome::Respond(response) = apply(
            &mut message,
            &budget,
            json!({"type":"respond","status":205}),
            b"",
            BodyMode::None,
        )
        .unwrap() else {
            panic!("HEAD response")
        };
        assert!(response.headers.is_empty());
    }

    #[tokio::test]
    async fn expired_stage_never_enters_backend_or_accepts_a_terminal_result() {
        let policy = Policy::compile(
            r#"targets:
  - origins: [https://a.example]
    rules:
      - name: must-not-execute
        match: {path-exact: /path}
        request:
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
"#,
        )
        .unwrap();
        let budget = Budget::default();
        let mut message = request(&budget);
        let original = message.original.url.clone();
        let result = run_until(
            &policy,
            &original,
            &mut message,
            &CancellationToken::new(),
            Instant::now() - Duration::from_millis(1),
        )
        .await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(message.request.url, original);
        assert_eq!(
            message.body.as_ref().unwrap().logical().unwrap(),
            b"original"
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let result = run_until(
            &policy,
            &original,
            &mut message,
            &cancelled,
            Instant::now() - Duration::from_millis(1),
        )
        .await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
    }
}

#[cfg(test)]
#[path = "script_message/borrowed_input_tests.rs"]
mod borrowed_input_tests;

#[cfg(all(test, target_vendor = "apple"))]
#[path = "script_message/guard_coverage_tests.rs"]
mod guard_coverage_tests;

#[cfg(all(test, unix))]
#[path = "script_message/mapped_output_tests.rs"]
mod mapped_output_tests;

#[cfg(all(test, target_vendor = "apple"))]
#[path = "script_message/plan_yield_tests.rs"]
mod plan_yield_tests;
