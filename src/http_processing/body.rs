//! Bounded, atomic content rewriting. Adapters retain their framing cursors.
use super::body_budget as budget;
#[path = "body_codec.rs"]
mod codec;
#[path = "body_json.rs"]
mod json;
#[path = "body_protobuf.rs"]
mod protobuf;
pub(crate) use budget::{Budget, BudgetedBytes, MAX_BODY};
pub(crate) use json::JsonFilter;
pub(crate) use protobuf::{ProtobufRemove, ProtobufRemoveSpec};

use super::{
    diagnostics::{self, BodyPoint, Counter},
    headers::Fields,
    rules::{BodyOperation, Phase, RequestMatch, Rule, RuleAction},
};
use bytes::Bytes;
#[cfg(test)]
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bypass {
    NoRules,
    ForbiddenBody,
    Streaming,
    Trailers,
    Charset,
    Encoding,
    IdentityExcluded,
    Budget,
    Size,
    InvalidText,
    Transform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Unsupported,
}

/// Capture before request-header actions. Content negotiation must reflect the
/// client that will actually receive the response, not a rewritten header.
#[derive(Clone, Copy)]
pub(crate) struct OriginalRequestMeta {
    pub(crate) head: bool,
    pub(crate) connect: bool,
    pub(crate) identity_allowed: bool,
}
impl OriginalRequestMeta {
    pub(crate) fn new(method: &str, fields: &Fields) -> Self {
        Self {
            head: method == "HEAD",
            connect: method == "CONNECT",
            identity_allowed: identity_allowed(
                fields
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
                    .map(|(_, value)| Some(value.as_str())),
            ),
        }
    }
}

pub(crate) struct WireBodyMeta {
    pub(crate) encoding: Encoding,
    pub(crate) length: Option<u64>,
    bypass: Option<Bypass>,
    media: NativeMedia,
}

#[derive(Clone, Copy, Default)]
struct NativeMedia {
    protobuf: Option<protobuf::MediaType>,
    invalid_charset: bool,
}
impl WireBodyMeta {
    pub(crate) fn new(
        fields: &Fields,
        original: &OriginalRequestMeta,
        phase: Phase,
        status: Option<u16>,
        length: Option<u64>,
        upgraded: bool,
    ) -> Self {
        let values = |name: &'static str| {
            fields
                .iter()
                .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        let mut encodings = values("content-encoding")
            .flat_map(|value| value.split(','))
            .map(str::trim);
        let encoding = match encodings.next() {
            None => Encoding::Identity,
            Some(value) if value.eq_ignore_ascii_case("identity") => Encoding::Identity,
            Some(value) if value.eq_ignore_ascii_case("gzip") => Encoding::Gzip,
            Some(value) if value.eq_ignore_ascii_case("deflate") => Encoding::Deflate,
            Some(value) if value.eq_ignore_ascii_case("br") => Encoding::Brotli,
            _ => Encoding::Unsupported,
        };
        let encoding = if encodings.next().is_some() {
            Encoding::Unsupported
        } else {
            encoding
        };
        let mut bypass = None;
        let mut media = NativeMedia::default();
        if original.head
            || original.connect
            || upgraded
            || status.is_some_and(|status| status < 200 || matches!(status, 204 | 205 | 304))
        {
            bypass = Some(Bypass::ForbiddenBody);
        } else if status == Some(206) || values("content-range").next().is_some() {
            bypass = Some(Bypass::Streaming);
        } else if values("trailer").next().is_some() {
            bypass = Some(Bypass::Trailers);
        } else if phase == Phase::Response && !original.identity_allowed {
            bypass = Some(Bypass::IdentityExcluded);
        }
        let mut content_types = 0;
        for content_type in values("content-type") {
            content_types += 1;
            let mut parts = content_type.split(';');
            let media_type = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            if content_types == 1 {
                media.protobuf = protobuf::MediaType::parse(&media_type, content_type);
            }
            if media_type == "text/event-stream"
                || media_type == "application/grpc"
                || media_type.starts_with("application/grpc+")
                || media_type.starts_with("multipart/")
            {
                bypass = Some(Bypass::Streaming);
            }
            for parameter in parts {
                if let Some((key, value)) = parameter.split_once('=')
                    && key.trim().eq_ignore_ascii_case("charset")
                    && !matches!(
                        value.trim().trim_matches('"').to_ascii_lowercase().as_str(),
                        "utf-8" | "utf8"
                    )
                {
                    media.invalid_charset = true;
                }
            }
        }
        if content_types > 1 {
            media.invalid_charset = true;
            media.protobuf = None;
        }
        Self {
            encoding,
            length,
            bypass,
            media,
        }
    }
    #[cfg(test)]
    fn eligibility(&self) -> Result<(), Bypass> {
        self.common_eligibility()?;
        if self.media.invalid_charset {
            return Err(Bypass::Charset);
        }
        Ok(())
    }
    pub(crate) fn common_eligibility(&self) -> Result<(), Bypass> {
        if let Some(reason) = self.bypass {
            return Err(reason);
        }
        if self.encoding == Encoding::Unsupported {
            return Err(Bypass::Encoding);
        }
        if self.length.is_some_and(|length| length > MAX_BODY as u64) {
            return Err(Bypass::Size);
        }
        Ok(())
    }
}

fn quality(value: &str) -> Option<u16> {
    let value = value.trim();
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(integer, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    let decimal = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u16>().ok()? * 10u16.pow(3 - fraction.len() as u32)
    };
    if integer == "1" {
        (decimal == 0).then_some(1000)
    } else {
        Some(decimal)
    }
}

pub(super) fn identity_allowed<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> bool {
    let mut identity = None;
    let mut wildcard = None;
    for value in values {
        let Some(value) = value else {
            return false;
        };
        for coding in value.split(',').filter(|coding| !coding.trim().is_empty()) {
            let mut parts = coding.split(';');
            let token = parts.next().unwrap_or_default().trim();
            let mut weight = 1000;
            let mut seen_quality = false;
            for parameter in parts {
                let Some((name, value)) = parameter.split_once('=') else {
                    return false;
                };
                if !name.trim().eq_ignore_ascii_case("q") || seen_quality {
                    return false;
                }
                let Some(parsed) = quality(value) else {
                    return false;
                };
                seen_quality = true;
                weight = parsed;
            }
            let slot = if token.eq_ignore_ascii_case("identity") {
                &mut identity
            } else if token == "*" {
                &mut wildcard
            } else {
                continue;
            };
            if slot.is_some() {
                return false;
            }
            *slot = Some(weight);
        }
    }
    identity.or(wildcard).is_none_or(|quality| quality != 0)
}

fn body_operations<'a, 'u>(
    rules: &'a [Rule],
    original: RequestMatch<'u>,
    phase: Phase,
    media: NativeMedia,
) -> impl Iterator<Item = &'a BodyOperation> + use<'a, 'u> {
    rules.iter().filter_map(move |rule| {
        let RuleAction::Body {
            phase: rule_phase,
            operation,
        } = &rule.action
        else {
            return None;
        };
        if *rule_phase != phase {
            return None;
        }
        match operation {
            BodyOperation::JsonPatch(patch) if patch.is_empty() => return None,
            BodyOperation::ProtobufRemove(filter) if !filter.matches(media.protobuf) => {
                return None;
            }
            _ => {}
        }
        rule.matches(original).then_some(operation)
    })
}

fn native_eligibility(
    rules: &[Rule],
    original: RequestMatch<'_>,
    phase: Phase,
    wire: &WireBodyMeta,
) -> Result<(), Bypass> {
    let mut operations = body_operations(rules, original, phase, wire.media);
    let first = operations.next().ok_or(Bypass::NoRules)?;
    wire.common_eligibility()?;
    if wire.media.invalid_charset
        && !std::iter::once(first)
            .chain(operations)
            .any(|operation| matches!(operation, BodyOperation::ProtobufRemove(_)))
    {
        return Err(Bypass::Charset);
    }
    Ok(())
}

pub(crate) struct Transaction<'a> {
    budget: Budget,
    raw: BudgetedBytes,
    rules: &'a [Rule],
    original: RequestMatch<'a>,
    phase: Phase,
    encoding: Encoding,
    media: NativeMedia,
}
pub(crate) struct ResultBody {
    pub(crate) body: BudgetedBytes,
    pub(crate) changed: bool,
    pub(crate) bypass: Option<Bypass>,
    original: Option<BudgetedBytes>,
    text: bool,
}
impl ResultBody {
    pub(crate) fn rollback(&mut self, reason: Bypass) {
        diagnostics::body_bypass(BodyPoint::HeaderFinalize, reason);
        if let Some(original) = self.original.take() {
            self.body = original;
        }
        self.changed = false;
        self.bypass = Some(reason);
    }
    pub(crate) fn finalize_headers(&mut self, fields: &mut Fields) {
        if !self.changed {
            return;
        }
        let mut candidate = fields.clone();
        repair_metadata_kind(&mut candidate, self.body.as_ref().len(), self.text);
        if super::headers::check(&candidate).is_ok() {
            *fields = candidate;
            self.original.take();
        } else {
            self.rollback(Bypass::Budget);
        }
    }
}

impl<'a> Transaction<'a> {
    pub(crate) fn begin(
        budget: &Budget,
        rules: &'a [Rule],
        original: impl Into<RequestMatch<'a>>,
        phase: Phase,
        wire: &WireBodyMeta,
    ) -> Result<Self, Bypass> {
        let original = original.into();
        diagnostics::increment(Counter::CollectorNativeRequested);
        let result = (|| {
            native_eligibility(rules, original, phase, wire)?;
            let capacity = wire.length.map_or(MAX_BODY + 1, |length| length as usize);
            let raw = BudgetedBytes::new(budget, capacity).ok_or(Bypass::Budget)?;
            Ok(Self {
                budget: budget.clone(),
                raw,
                rules,
                original,
                phase,
                encoding: wire.encoding,
                media: wire.media,
            })
        })();
        match &result {
            Ok(_) => diagnostics::increment(Counter::CollectorAdmitted),
            Err(reason) => diagnostics::body_bypass(BodyPoint::NativeAdmission, *reason),
        }
        result
    }
    /// Shared collection admits binary scripts independently of native text
    /// rules. The same collector and codec still own the wire representation.
    pub(crate) fn begin_shared(
        budget: &Budget,
        rules: &'a [Rule],
        original: impl Into<RequestMatch<'a>>,
        phase: Phase,
        wire: &WireBodyMeta,
        script_body: bool,
    ) -> Result<Self, Bypass> {
        let original = original.into();
        diagnostics::increment(Counter::CollectorSharedRequested);
        let result = (|| {
            if script_body {
                wire.common_eligibility()?;
            } else {
                native_eligibility(rules, original, phase, wire)?;
            }
            let capacity = wire.length.map_or(MAX_BODY + 1, |length| length as usize);
            Ok(Self {
                budget: budget.clone(),
                raw: BudgetedBytes::new_shared_collector(budget, capacity, wire.length.is_some())
                    .ok_or(Bypass::Budget)?,
                rules,
                original,
                phase,
                encoding: wire.encoding,
                media: wire.media,
            })
        })();
        match &result {
            Ok(_) => diagnostics::increment(Counter::CollectorAdmitted),
            Err(reason) => diagnostics::body_bypass(BodyPoint::SharedAdmission, *reason),
        }
        result
    }
    pub(crate) fn remaining(&self) -> usize {
        self.raw.remaining()
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), Bypass> {
        self.raw.extend(bytes).map_err(|_| {
            diagnostics::body_bypass(BodyPoint::Collection, Bypass::Size);
            Bypass::Size
        })?;
        if self.raw.as_ref().len() > MAX_BODY {
            diagnostics::body_bypass(BodyPoint::Collection, Bypass::Size);
            return Err(Bypass::Size);
        }
        Ok(())
    }
    pub(crate) fn into_raw(self) -> BudgetedBytes {
        self.raw
    }
    pub(crate) fn finish(self, has_trailers: bool) -> ResultBody {
        diagnostics::increment(Counter::CollectorFinished);
        let fallback = |raw, reason, point| {
            diagnostics::body_bypass(point, reason);
            ResultBody {
                body: raw,
                changed: false,
                bypass: Some(reason),
                original: None,
                text: false,
            }
        };
        if has_trailers {
            return fallback(self.raw, Bypass::Trailers, BodyPoint::NativeDecode);
        }
        if self.raw.as_ref().len() > MAX_BODY {
            return fallback(self.raw, Bypass::Size, BodyPoint::NativeDecode);
        }
        let decoded = match codec::decode(self.raw.as_ref(), self.encoding, &self.budget) {
            Ok(decoded) => decoded,
            Err(reason) => return fallback(self.raw, reason, BodyPoint::NativeDecode),
        };
        let baseline = decoded
            .as_ref()
            .map_or(self.raw.as_ref(), |value| value.as_ref());
        let candidate = match apply_operations(
            self.rules,
            self.original,
            self.phase,
            baseline,
            &self.budget,
            self.media,
        ) {
            Ok(candidate) => candidate,
            Err(reason) => {
                return ResultBody {
                    body: self.raw,
                    changed: false,
                    bypass: Some(reason),
                    original: None,
                    text: false,
                };
            }
        };
        match candidate {
            Some(output) if output.bytes.as_ref() != baseline => ResultBody {
                body: output.bytes,
                changed: true,
                bypass: None,
                original: Some(self.raw),
                text: output.text,
            },
            _ => ResultBody {
                body: self.raw,
                changed: false,
                bypass: None,
                original: None,
                text: false,
            },
        }
    }

    /// Finish native work while retaining the decoded baseline for scripts.
    /// A native failure does not invalidate a successfully decoded entity.
    pub(crate) fn finish_shared(self, has_trailers: bool, fields: &mut Fields) -> Entity {
        diagnostics::increment(Counter::CollectorFinished);
        let decoded = if has_trailers {
            Err(Bypass::Trailers)
        } else if self.raw.as_ref().len() > MAX_BODY {
            Err(Bypass::Size)
        } else {
            codec::decode(self.raw.as_ref(), self.encoding, &self.budget)
        };
        let wire = self.raw.into_bytes();
        let mut entity = match decoded {
            Ok(decoded) => Entity {
                logical: Some(decoded.map_or_else(|| wire.clone(), BudgetedBytes::into_bytes)),
                wire,
                budget: self.budget.clone(),
                bypass: None,
                changed: false,
                original_text: !self.media.invalid_charset,
            },
            Err(reason) => {
                diagnostics::body_bypass(BodyPoint::SharedDecode, reason);
                return Entity {
                    wire,
                    logical: None,
                    budget: self.budget.clone(),
                    bypass: Some(reason),
                    changed: false,
                    original_text: !self.media.invalid_charset,
                };
            }
        };
        if body_operations(self.rules, self.original, self.phase, self.media)
            .next()
            .is_none()
        {
            return entity;
        }
        let baseline = entity.logical().expect("decoded entity");
        match apply_operations(
            self.rules,
            self.original,
            self.phase,
            baseline,
            &self.budget,
            self.media,
        ) {
            Ok(Some(output)) if output.bytes.as_ref() != baseline => {
                if let Err(reason) = commit_shared_body(&mut entity, fields, output) {
                    diagnostics::body_bypass(BodyPoint::HeaderFinalize, reason);
                    entity.bypass = Some(reason);
                }
            }
            Ok(_) => {}
            Err(reason) => entity.bypass = Some(reason),
        }
        entity
    }
}

/// A read-only body view tied to its actual Entity or BudgetedBytes owner.
/// Private fields prevent pairing arbitrary bytes with a different ledger.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(feature = "inbound-http", target_os = "tvos")),
    allow(dead_code)
)]
pub(crate) struct BorrowedBody<'a> {
    bytes: &'a [u8],
    budget: &'a Budget,
}
#[cfg_attr(
    not(all(feature = "inbound-http", target_os = "tvos")),
    allow(dead_code)
)]
impl<'a> BorrowedBody<'a> {
    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub(crate) fn same_ledger_as(&self, output: &BudgetedBytes) -> bool {
        self.budget.same_ledger(output.budget())
    }
}
impl BudgetedBytes {
    #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
    pub(crate) fn borrowed_body(&self) -> BorrowedBody<'_> {
        BorrowedBody {
            bytes: self.as_ref(),
            budget: self.budget(),
        }
    }
}

/// Complete wire representation and its decoded logical view. `Bytes` keeps
/// the original allocation's workspace permit through clones and send queues.
#[derive(Clone)]
pub(crate) struct Entity {
    wire: Bytes,
    logical: Option<Bytes>,
    // Provenance only: the reservation still belongs to the actual Bytes owner.
    budget: Budget,
    pub(crate) bypass: Option<Bypass>,
    changed: bool,
    original_text: bool,
}
impl Entity {
    #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
    pub(crate) fn identity(bytes: BudgetedBytes) -> Self {
        let budget = bytes.budget().clone();
        let wire = bytes.into_bytes();
        Self {
            logical: Some(wire.clone()),
            wire,
            budget,
            bypass: None,
            changed: false,
            original_text: true,
        }
    }
    pub(crate) fn wire(&self) -> &Bytes {
        &self.wire
    }
    pub(crate) fn logical(&self) -> Option<&[u8]> {
        self.logical.as_deref()
    }
    #[cfg_attr(
        not(all(feature = "inbound-http", target_os = "tvos")),
        allow(dead_code)
    )]
    pub(crate) fn borrowed_body(&self) -> Option<BorrowedBody<'_>> {
        Some(BorrowedBody {
            bytes: self.logical.as_deref()?,
            budget: &self.budget,
        })
    }
    pub(crate) fn into_wire(self) -> Bytes {
        self.wire
    }
    pub(crate) fn changed(&self) -> bool {
        self.changed
    }
    pub(crate) fn original_text_allowed(&self) -> bool {
        self.original_text
    }
    /// Reject a foreign owner before changing any part of this Entity.
    pub(crate) fn replace(&mut self, bytes: BudgetedBytes) -> Result<(), BudgetedBytes> {
        if !self.budget.same_ledger(bytes.budget()) {
            return Err(bytes);
        }
        let bytes = bytes.into_bytes();
        self.wire = bytes.clone();
        self.logical = Some(bytes);
        self.bypass = None;
        self.changed = true;
        Ok(())
    }
}

/// Commit only after both header validation and owner provenance have passed.
fn commit_shared_body(
    entity: &mut Entity,
    fields: &mut Fields,
    output: BodyCandidate,
) -> Result<(), Bypass> {
    let mut candidate = fields.clone();
    repair_metadata_kind(&mut candidate, output.bytes.as_ref().len(), output.text);
    super::headers::check(&candidate).map_err(|_| Bypass::Budget)?;
    entity.replace(output.bytes).map_err(|_| Bypass::Budget)?;
    *fields = candidate;
    Ok(())
}

struct BodyCandidate {
    bytes: BudgetedBytes,
    text: bool,
}

fn apply_operations<'a>(
    rules: &[Rule],
    original: impl Into<RequestMatch<'a>>,
    phase: Phase,
    baseline: &[u8],
    budget: &Budget,
    media: NativeMedia,
) -> Result<Option<BodyCandidate>, Bypass> {
    let original = original.into();
    diagnostics::increment(Counter::NativeTransformRequested);
    let result = (|| {
        let mut candidate: Option<BodyCandidate> = None;
        let mut verified_text = false;
        for operation in body_operations(rules, original, phase, media) {
            let input = candidate
                .as_ref()
                .map_or(baseline, |value| value.bytes.as_ref());
            if let BodyOperation::ProtobufRemove(filter) = operation {
                if let Some(bytes) = filter.apply(input, budget)? {
                    candidate = Some(BodyCandidate { bytes, text: false });
                }
                continue;
            }
            if !verified_text {
                if media.invalid_charset {
                    return Err(Bypass::Charset);
                }
                std::str::from_utf8(baseline).map_err(|_| Bypass::InvalidText)?;
                verified_text = true;
            }
            match operation {
                BodyOperation::Set(value) => {
                    let bytes =
                        BudgetedBytes::copy(budget, value.as_bytes()).ok_or(Bypass::Budget)?;
                    candidate = Some(BodyCandidate { bytes, text: true });
                }
                BodyOperation::Replace(search) => {
                    let input = std::str::from_utf8(input).map_err(|_| Bypass::InvalidText)?;
                    let capacity = search.output_capacity(input.len(), MAX_BODY);
                    let mut output =
                        if search.ascii_literal_byte_map().is_some() && capacity == input.len() {
                            BudgetedBytes::new_fixed_output(budget, capacity)
                        } else {
                            BudgetedBytes::new(budget, capacity)
                        }
                        .ok_or(Bypass::Budget)?;
                    fill_replacement(input, search, &mut output)?;
                    candidate = Some(BodyCandidate {
                        bytes: output,
                        text: true,
                    });
                }
                BodyOperation::JsonPatch(patch) => {
                    let input = std::str::from_utf8(input).map_err(|_| Bypass::InvalidText)?;
                    let bytes = json::apply(input, patch, budget)?;
                    candidate = Some(BodyCandidate { bytes, text: true });
                }
                BodyOperation::JsonFilter(filter) => {
                    let input = std::str::from_utf8(input).map_err(|_| Bypass::InvalidText)?;
                    if let Some(bytes) = filter.apply(input, budget)? {
                        candidate = Some(BodyCandidate { bytes, text: true });
                    }
                }
                BodyOperation::ProtobufRemove(_) => unreachable!("binary operation handled above"),
            }
        }
        Ok(candidate)
    })();
    diagnostics::increment(Counter::NativeTransformFinished);
    if let Err(reason) = &result {
        diagnostics::body_bypass(BodyPoint::NativeTransform, *reason);
    }
    result
}

/// Caller has validated UTF-8 and admitted the unchanged independent output.
fn fill_replacement(
    input: &str,
    search: &super::rules::Search,
    output: &mut BudgetedBytes,
) -> Result<(), Bypass> {
    if let Some((search, replacement, occurrences)) = search.ascii_literal_byte_map() {
        // Admission is unchanged, including no-match/same-byte. ASCII bytes
        // cannot occur within multibyte UTF-8 units. Dollar/NUL are literal data.
        output
            .write_initialized_output(input.len(), |output| {
                if occurrences == super::rules::Occurrences::First {
                    output.copy_from_slice(input.as_bytes());
                    if let Some(index) = input.find(char::from(search)) {
                        output[index] = replacement;
                    }
                } else {
                    for (output, input) in output.iter_mut().zip(input.as_bytes()) {
                        *output = if *input == search {
                            replacement
                        } else {
                            *input
                        };
                    }
                }
                Ok(input.len())
            })
            .map_err(|_| Bypass::Transform)
    } else {
        output
            .write_text(|output| search.apply_into(input, output, MAX_BODY))
            .map_err(|_| Bypass::Transform)
    }
}

/// Final representation repair follows successful content changes and therefore
/// takes precedence over independently successful ordinary header actions.
pub(crate) fn repair_metadata_kind(fields: &mut Fields, length: usize, text: bool) {
    fields.retain(|(name, _)| {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "content-length"
                | "transfer-encoding"
                | "content-encoding"
                | "etag"
                | "last-modified"
                | "content-md5"
                | "content-digest"
                | "repr-digest"
                | "signature"
                | "signature-input"
                | "accept-ranges"
                | "content-range"
        )
    });
    for (name, value) in fields.iter_mut() {
        if text && name.eq_ignore_ascii_case("content-type") {
            let mut pieces = value.split(';');
            let mut repaired = pieces.next().unwrap_or_default().to_owned();
            for parameter in pieces {
                if parameter
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("charset"))
                {
                    continue;
                }
                repaired.push(';');
                repaired.push_str(parameter);
            }
            repaired.push_str("; charset=utf-8");
            *value = repaired;
        }
    }
    fields.push(("Content-Length".into(), length.to_string()));
}

#[cfg(all(test, feature = "inbound-http"))]
#[path = "body_p1_tests.rs"]
mod p1_tests;

#[cfg(all(
    feature = "inbound-http",
    feature = "http-diagnostics",
    target_os = "tvos"
))]
#[path = "native_byte_map_validation.rs"]
mod native_byte_map_validation;
#[cfg(all(
    feature = "inbound-http",
    feature = "http-diagnostics",
    target_os = "tvos"
))]
pub(crate) fn validate_native_byte_map() -> std::io::Result<serde_json::Value> {
    native_byte_map_validation::run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, feature = "inbound-http"))]
    #[forbid(unsafe_code)]
    mod shared_collector_mapping_tests {
        include!("shared_collector_body_memory_tests.rs");
    }

    #[test]
    fn borrowed_body_factories_borrow_the_same_allocation_and_actual_ledger() {
        let budget = Budget::default();
        let input = BudgetedBytes::copy(&budget, b"paid\0input").unwrap();
        let local_output = BudgetedBytes::empty(&budget);
        let foreign_output = BudgetedBytes::empty(&Budget::default());
        let original_charge = budget.used();
        {
            let view = input.borrowed_body();
            assert_eq!(view.as_bytes().as_ptr(), input.as_ref().as_ptr());
            assert_eq!(view.as_bytes(), b"paid\0input");
            assert!(view.same_ledger_as(&local_output));
            assert!(!view.same_ledger_as(&foreign_output));
            assert_eq!(budget.used(), original_charge);
        }
        let entity = Entity::identity(input);
        let clone = entity.clone();
        {
            let view = entity.borrowed_body().unwrap();
            assert_eq!(view.as_bytes().as_ptr(), clone.logical().unwrap().as_ptr());
            assert!(view.same_ledger_as(&local_output));
            assert!(!view.same_ledger_as(&foreign_output));
            assert_eq!(budget.used(), original_charge);
        }
        drop(entity);
        assert_eq!(budget.used(), original_charge);
        drop(clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn shared_native_commit_keeps_body_and_metadata_atomic_on_foreign_owner() {
        let budget = Budget::default();
        let foreign = Budget::default();
        let mut entity = Entity::identity(BudgetedBytes::copy(&budget, b"original").unwrap());
        let original_wire = entity.wire().clone();
        let mut fields = vec![
            ("Content-Length".into(), "8".into()),
            ("ETag".into(), "original-tag".into()),
            ("Content-Type".into(), "text/plain".into()),
        ];
        let before = fields.clone();
        let output = BudgetedBytes::copy(&foreign, b"foreign-longer").unwrap();
        assert_eq!(
            commit_shared_body(
                &mut entity,
                &mut fields,
                BodyCandidate {
                    bytes: output,
                    text: true
                }
            ),
            Err(Bypass::Budget)
        );
        assert_eq!(fields, before);
        assert_eq!(entity.wire().as_ptr(), original_wire.as_ptr());
        assert_eq!(entity.logical().unwrap(), b"original");
        assert!(!entity.changed());
        assert_eq!(foreign.used(), 0);

        // The same production helper really commits a correctly paid owner.
        let output = BudgetedBytes::copy(&budget, b"accepted-longer").unwrap();
        assert_eq!(
            commit_shared_body(
                &mut entity,
                &mut fields,
                BodyCandidate {
                    bytes: output,
                    text: true
                }
            ),
            Ok(())
        );
        assert_eq!(entity.logical().unwrap(), b"accepted-longer");
        assert!(entity.changed());
        assert!(
            fields
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v == "15")
        );
        assert!(!fields.iter().any(|(k, _)| k.eq_ignore_ascii_case("etag")));
        drop(entity);
        assert_eq!(budget.used(), BudgetedBytes::allocation_cost(8).unwrap());
        drop(original_wire);
        assert_eq!(budget.used(), 0);
    }

    #[cfg(feature = "inbound-http")]
    #[tokio::test]
    async fn borrowed_entity_owner_stays_charged_during_the_actual_blocked_sender() {
        let budget = Budget::default();
        let entity = Entity::identity(BudgetedBytes::copy(&budget, &vec![b'x'; 4096]).unwrap());
        let cost = budget.used();
        {
            let view = entity.borrowed_body().unwrap();
            assert_eq!(view.as_bytes(), &vec![b'x'; 4096]);
            assert_eq!(budget.used(), cost);
        }
        let wire = entity.into_wire();
        let last_slice = wire.slice(17..18);
        let prepared = super::super::h1_body::PreparedBody::from_bytes(wire);
        let mut reader = tokio::io::BufReader::new(tokio::io::empty());
        let (mut writer, peer) = tokio::io::duplex(8);
        let blocklist = std::collections::HashSet::new();
        let mut sending = Box::pin(prepared.transfer(
            &mut reader,
            &mut writer,
            std::time::Duration::from_secs(1),
            &blocklist,
            false,
        ));
        // An 8-byte duplex cannot finish the real 4096-byte write_all. No
        // spawned task needs cleanup if an assertion unwinds this test.
        assert!(futures_util::poll!(sending.as_mut()).is_pending());
        assert_eq!(budget.used(), cost);
        drop(sending);
        drop(peer);
        assert_eq!(budget.used(), cost);
        assert_eq!(last_slice.as_ref(), b"x");
        drop(last_slice);
        assert_eq!(budget.used(), 0);
    }

    #[cfg(all(unix, feature = "inbound-http"))]
    #[test]
    fn native_fixed_outputs_select_backing_and_keep_source_and_sender_owners_paid() {
        const SUFFIX: &[u8] = "é😀中\0$".as_bytes();
        let url = Url::parse("https://fixed-output.invalid/body").unwrap();
        for capacity in [64 * 1024 - 1, 64 * 1024, MAX_BODY] {
            for occurrences in ["first", "all"] {
                let budget = Budget::default();
                let mut source = BudgetedBytes::new(&budget, capacity).unwrap();
                source
                    .write_initialized_output(capacity, |bytes| {
                        bytes.fill(b'q');
                        bytes[capacity - SUFFIX.len()..].copy_from_slice(SUFFIX);
                        Ok(capacity)
                    })
                    .unwrap();
                assert!(!source.is_mapped_for_test());
                let mut entity = Entity::identity(source);
                let original = std::str::from_utf8(entity.logical().unwrap()).unwrap();
                let expected = if occurrences == "first" {
                    original.replacen('q', "z", 1)
                } else {
                    original.replace('q', "z")
                };
                let selected = rules(&format!(
                    "- {{url: '.', action: response-body-replace, search: q, replacement: z, occurrences: {occurrences}}}"
                ));
                let output = apply_operations(
                    &selected,
                    &url,
                    Phase::Response,
                    entity.logical().unwrap(),
                    &budget,
                    NativeMedia::default(),
                )
                .unwrap()
                .unwrap();
                assert_eq!(output.bytes.is_mapped_for_test(), capacity >= 64 * 1024);
                assert_eq!(output.bytes.as_ref(), expected.as_bytes());
                assert!(std::str::from_utf8(output.bytes.as_ref()).is_ok());
                assert_ne!(
                    output.bytes.as_ref().as_ptr(),
                    entity.logical().unwrap().as_ptr()
                );
                let cost = BudgetedBytes::allocation_cost(capacity).unwrap();
                assert_eq!(budget.used(), 2 * cost);
                let source_sender = entity.wire().slice(..1);
                let mut fields = vec![("ETag".into(), "old".into())];
                commit_shared_body(&mut entity, &mut fields, output).unwrap();
                assert!(entity.changed());
                assert_eq!(budget.used(), 2 * cost);
                let sender = entity.into_wire();
                let last_output = sender.slice(capacity - 1..);
                drop(sender);
                assert_eq!(last_output.as_ref(), &expected.as_bytes()[capacity - 1..]);
                assert_eq!(source_sender.as_ref(), b"q");
                assert_eq!(budget.used(), 2 * cost);
                drop(source_sender);
                assert_eq!(budget.used(), cost);
                drop(last_output);
                assert_eq!(budget.used(), 0);
            }
        }
    }

    #[cfg(all(unix, feature = "inbound-http"))]
    #[test]
    fn native_fixed_output_keeps_noop_representation_and_whole_stage_rollback() {
        let url = Url::parse("https://fixed-output.invalid/body").unwrap();
        let original = vec![b'q'; 64 * 1024];
        for (yaml, bypass) in [
            (
                "- {url: '.', action: request-body-replace, search: q, replacement: q}",
                None,
            ),
            (
                "- {url: '.', action: request-body-replace, search: x, replacement: z}",
                None,
            ),
            (
                "- {url: '.', action: request-body-replace, search: q, replacement: z}\n- {url: '.', action: request-body-json-patch, patch: [{op: test, path: /ok, value: false}]}",
                Some(Bypass::Transform),
            ),
        ] {
            let budget = Budget::default();
            let selected = rules(yaml);
            let mut fields = vec![
                ("ETag".into(), "old".into()),
                ("X-Independent".into(), "kept".into()),
            ];
            let before = fields.clone();
            let request = OriginalRequestMeta::new("POST", &fields);
            let wire = WireBodyMeta::new(
                &fields,
                &request,
                Phase::Request,
                None,
                Some(original.len() as u64),
                false,
            );
            let mut transaction =
                Transaction::begin_shared(&budget, &selected, &url, Phase::Request, &wire, true)
                    .unwrap();
            transaction.push(&original).unwrap();
            let entity = transaction.finish_shared(false, &mut fields);
            assert!(!entity.changed());
            assert_eq!(entity.bypass, bypass);
            assert_eq!(entity.logical().unwrap(), original.as_slice());
            assert_eq!(entity.wire().as_ref(), original.as_slice());
            assert_eq!(fields, before);
            assert_eq!(
                budget.used(),
                BudgetedBytes::allocation_cost(original.len()).unwrap()
            );
            drop(entity);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn literal_capacity_keeps_a_second_real_transaction_admissible_under_pressure() {
        const LENGTH: usize = 65536;
        let budget = Budget::default();
        let rules = rules("- {url: '.', action: response-body-replace, search: q, replacement: z}");
        let url = Url::parse("http://capacity.example/").unwrap();
        let request = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(
            &vec![],
            &request,
            Phase::Response,
            Some(200),
            Some(LENGTH as u64),
            false,
        );
        let small = BudgetedBytes::allocation_cost(LENGTH).unwrap();
        let old_maximum = BudgetedBytes::allocation_cost(MAX_BODY).unwrap();
        // This fixed pressure still lets the old implementation finish the
        // first real transform at its original raw + MAX allocation peak.
        let pressure = budget
            .reserve(budget::WORKSPACE - small - old_maximum)
            .unwrap();
        let mut first =
            Transaction::begin_shared(&budget, &rules, &url, Phase::Response, &wire, true).unwrap();
        first.push(&vec![b'q'; LENGTH]).unwrap();
        let first = first.finish_shared(false, &mut vec![]);
        assert!(first.changed());
        // Old MAX residency leaves exactly one raw slot; the extra byte makes
        // the second genuine collector fail rather than simulating a reserve.
        let boundary = budget.reserve(1).unwrap();
        let mut second =
            Transaction::begin_shared(&budget, &rules, &url, Phase::Response, &wire, true)
                .expect("retained literal output must leave the second real collector admissible");
        second.push(&vec![b'q'; LENGTH]).unwrap();
        let second = second.finish_shared(false, &mut vec![]);
        assert!(second.changed());
        assert_eq!(second.bypass, None);
        assert_eq!(second.wire().as_ref(), vec![b'z'; LENGTH]);
        assert_eq!(
            budget.used(),
            budget::WORKSPACE - small - old_maximum + 1 + 2 * small
        );
        drop(second);
        drop(first);
        drop(boundary);
        drop(pressure);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn literal_capacity_regex_and_growth_keep_full_capacity_and_budget_fallback() {
        let url = Url::parse("http://capacity.example/").unwrap();
        for yaml in [
            "- {url: '.', action: request-body-replace, search: a, replacement: aa}",
            "- {url: '.', action: request-body-replace, search: '(a)', search-mode: regex, replacement: '${1}'}",
        ] {
            let rules = rules(yaml);
            let budget = Budget::default();
            let output = apply_operations(
                &rules,
                &url,
                Phase::Request,
                b"a",
                &budget,
                NativeMedia::default(),
            )
            .unwrap()
            .unwrap()
            .bytes;
            assert_eq!(output.remaining() + output.as_ref().len(), MAX_BODY);
            assert_eq!(
                budget.used(),
                BudgetedBytes::allocation_cost(MAX_BODY).unwrap()
            );
            drop(output);
            let request = OriginalRequestMeta::new("POST", &vec![]);
            let wire = WireBodyMeta::new(&vec![], &request, Phase::Request, None, Some(1), false);
            let mut transaction =
                Transaction::begin_shared(&budget, &rules, &url, Phase::Request, &wire, true)
                    .unwrap();
            transaction.push(b"a").unwrap();
            let pressure = budget
                .reserve(
                    budget::WORKSPACE - budget.used() - BudgetedBytes::allocation_cost(1).unwrap(),
                )
                .unwrap();
            let entity = transaction.finish_shared(false, &mut vec![]);
            assert!(!entity.changed());
            assert_eq!(entity.bypass, Some(Bypass::Budget));
            assert_eq!(entity.wire().as_ref(), b"a");
            drop(entity);
            drop(pressure);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn shared_native_failure_keeps_decoded_entity_and_original_compressed_wire() {
        use std::io::Write;
        let budget = Budget::default();
        let rules = rules(
            "- {url: '.', action: request-body-json-patch, patch: [{op: test, path: /ok, value: false}]}",
        );
        let fields = vec![("Content-Encoding".into(), "gzip".into())];
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(br#"{"ok":true}"#).unwrap();
        let gzip = gzip.finish().unwrap();
        let meta = OriginalRequestMeta::new("POST", &fields);
        let wire = WireBodyMeta::new(
            &fields,
            &meta,
            Phase::Request,
            None,
            Some(gzip.len() as u64),
            false,
        );
        let original = Url::parse("http://example.com/").unwrap();
        let mut transaction =
            Transaction::begin_shared(&budget, &rules, &original, Phase::Request, &wire, true)
                .unwrap();
        transaction.push(&gzip).unwrap();
        let mut final_fields = fields.clone();
        let entity = transaction.finish_shared(false, &mut final_fields);
        assert_eq!(entity.logical().unwrap(), br#"{"ok":true}"#);
        assert_eq!(entity.wire().as_ref(), gzip);
        assert!(!entity.changed());
        assert_eq!(final_fields, fields);
        assert!(entity.bypass.is_some());
        let retained = entity.clone();
        drop(entity);
        assert!(budget.used() > 0);
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn shared_binary_input_survives_native_text_exclusion_and_decode_failure_is_unavailable() {
        let budget = Budget::default();
        let rules = rules("- {url: '.', action: request-body-set, value: changed}");
        let original = Url::parse("http://example.com/").unwrap();
        let fields = vec![(
            "Content-Type".into(),
            "application/octet-stream; charset=latin1".into(),
        )];
        let meta = OriginalRequestMeta::new("POST", &fields);
        let wire = WireBodyMeta::new(&fields, &meta, Phase::Request, None, Some(2), false);
        assert!(matches!(
            Transaction::begin(&budget, &rules, &original, Phase::Request, &wire),
            Err(Bypass::Charset)
        ));
        let mut transaction =
            Transaction::begin_shared(&budget, &rules, &original, Phase::Request, &wire, true)
                .unwrap();
        transaction.push(&[0xff, 0x00]).unwrap();
        let mut final_fields = fields.clone();
        let entity = transaction.finish_shared(false, &mut final_fields);
        assert_eq!(entity.logical().unwrap(), &[0xff, 0x00]);
        assert!(!entity.original_text_allowed());
        drop(entity);
        let fields = vec![("Content-Encoding".into(), "gzip".into())];
        let wire = WireBodyMeta::new(&fields, &meta, Phase::Request, None, Some(3), false);
        let mut transaction =
            Transaction::begin_shared(&budget, &[], &original, Phase::Request, &wire, true)
                .unwrap();
        transaction.push(b"bad").unwrap();
        let entity = transaction.finish_shared(false, &mut vec![]);
        assert!(entity.logical().is_none());
        assert_eq!(entity.wire().as_ref(), b"bad");
        drop(entity);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn shared_native_success_releases_old_representation_and_repairs_before_acceptance() {
        let budget = Budget::default();
        let rules = rules("- {url: '.', action: request-body-set, value: changed}");
        let original = Url::parse("http://example.com/").unwrap();
        let mut fields = vec![("ETag".into(), "old".into())];
        let meta = OriginalRequestMeta::new("POST", &fields);
        let wire = WireBodyMeta::new(&fields, &meta, Phase::Request, None, Some(8), false);
        let mut transaction =
            Transaction::begin_shared(&budget, &rules, &original, Phase::Request, &wire, true)
                .unwrap();
        transaction.push(b"original").unwrap();
        let entity = transaction.finish_shared(false, &mut fields);
        assert!(entity.changed());
        assert_eq!(entity.wire().as_ref(), b"changed");
        assert!(
            !fields
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("etag"))
        );
        assert!(budget.used() < 1024);
        drop(entity);
        assert_eq!(budget.used(), 0);
        let no_content =
            WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(205), Some(0), false);
        assert!(matches!(
            no_content.common_eligibility(),
            Err(Bypass::ForbiddenBody)
        ));
    }
    fn rules(yaml: &str) -> Vec<Rule> {
        let raw: Vec<super::super::rules::RawRule> = serde_yaml_ng::from_str(yaml).unwrap();
        let mut total = 0;
        raw.into_iter()
            .map(|raw| Rule::compile(raw, &mut total).unwrap())
            .collect()
    }
    #[test]
    fn identity_negotiation_uses_specific_weight_and_original_metadata() {
        for (text, allowed) in [
            ("gzip", true),
            ("identity;q=0", false),
            ("*;q=0", false),
            ("*;q=0, identity;q=0.5", true),
            ("identity;q=0, *;q=1", false),
        ] {
            let request =
                OriginalRequestMeta::new("GET", &vec![("Accept-Encoding".into(), text.into())]);
            assert_eq!(request.identity_allowed, allowed);
            let wire = WireBodyMeta::new(
                &vec![],
                &request,
                Phase::Response,
                Some(200),
                Some(0),
                false,
            );
            assert_eq!(wire.eligibility().is_ok(), allowed);
        }
    }
    #[test]
    fn bounded_set_holds_raw_until_success_and_preserves_trailer_original() {
        let rules = rules("- {url: '.', action: response-body-set, value: changed}");
        let url = Url::parse("http://a.example/").unwrap();
        let request = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(
            &vec![],
            &request,
            Phase::Response,
            Some(200),
            Some(8),
            false,
        );
        let budget = Budget::default();
        for trailers in [false, true] {
            let mut transaction =
                Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
            transaction.push(b"original").unwrap();
            let result = transaction.finish(trailers);
            assert_eq!(result.changed, !trailers);
            assert_eq!(
                result.body.as_ref(),
                if trailers {
                    b"original".as_slice()
                } else {
                    b"changed".as_slice()
                }
            );
        }
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn body_exclusions_use_wire_metadata_and_allow_normal_zero_bodies() {
        let request = OriginalRequestMeta::new("GET", &vec![]);
        for (name, value) in [
            ("Content-Type", "text/event-stream"),
            ("Content-Type", "application/json; charset=iso-8859-1"),
            ("Trailer", "X-Final"),
            ("Content-Range", "bytes 0-1/3"),
        ] {
            let wire = WireBodyMeta::new(
                &vec![(name.into(), value.into())],
                &request,
                Phase::Response,
                Some(200),
                Some(0),
                false,
            );
            assert!(wire.eligibility().is_err());
        }
        assert!(
            WireBodyMeta::new(
                &vec![],
                &request,
                Phase::Response,
                Some(200),
                Some(0),
                false
            )
            .eligibility()
            .is_ok()
        );
        assert!(
            WireBodyMeta::new(
                &vec![],
                &request,
                Phase::Response,
                Some(204),
                Some(0),
                false
            )
            .eligibility()
            .is_err()
        );
    }

    #[test]
    fn text_rules_accumulate_but_failed_patch_restores_the_entire_stage() {
        let url = Url::parse("https://a.example/").unwrap();
        let meta = OriginalRequestMeta::new("POST", &vec![]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Request, None, Some(8), false);
        let budget = Budget::default();
        let text = rules(
            r#"
- {url: '.', action: request-body-set, value: 'a=1,b=2'}
- {url: '.', action: request-body-replace, search: '([0-9])', search-mode: regex, replacement: '${1}0'}
"#,
        );
        let mut transaction =
            Transaction::begin(&budget, &text, &url, Phase::Request, &wire).unwrap();
        transaction.push(b"original").unwrap();
        let mut result = transaction.finish(false);
        let mut fields = vec![
            ("Content-MD5".into(), "old".into()),
            ("Content-Type".into(), "text/plain; charset=ascii".into()),
        ];
        result.finalize_headers(&mut fields);
        assert!(result.changed);
        assert_eq!(result.body.as_ref(), b"a=10,b=20");
        assert!(
            fields
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("content-md5"))
        );
        assert!(
            fields
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
                    && value == "text/plain; charset=utf-8")
        );
        drop(result);
        let failed = rules(
            r#"
- {url: '.', action: request-body-set, value: '{"ok":true}'}
- {url: '.', action: request-body-json-patch, patch: [{op: test, path: /ok, value: false}]}
"#,
        );
        let mut transaction =
            Transaction::begin(&budget, &failed, &url, Phase::Request, &wire).unwrap();
        transaction.push(b"original").unwrap();
        let result = transaction.finish(false);
        assert!(!result.changed);
        assert_eq!(result.body.as_ref(), b"original");
        assert_eq!(result.bypass, Some(Bypass::Transform));
        drop(result);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn header_repair_failure_keeps_raw_and_independent_header_actions() {
        let rules = rules("- {url: '.', action: response-body-set, value: changed}");
        let url = Url::parse("http://a.example/").unwrap();
        let request = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(
            &vec![],
            &request,
            Phase::Response,
            Some(200),
            Some(8),
            false,
        );
        let budget = Budget::default();
        let mut transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        transaction.push(b"original").unwrap();
        let mut result = transaction.finish(false);
        let mut fields = vec![("X-Independent".into(), "kept".into()); 100];
        result.finalize_headers(&mut fields);
        assert!(!result.changed);
        assert_eq!(result.bypass, Some(Bypass::Budget));
        assert_eq!(result.body.as_ref(), b"original");
        assert_eq!(fields.len(), 100);
    }

    #[test]
    fn compressed_noop_retains_original_representation() {
        use std::io::Write;
        let rules = rules("- {url: '.', action: response-body-set, value: original}");
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"original").unwrap();
        let gzip = gzip.finish().unwrap();
        let url = Url::parse("http://a.example/").unwrap();
        let request = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(
            &vec![("Content-Encoding".into(), "gzip".into())],
            &request,
            Phase::Response,
            Some(200),
            Some(gzip.len() as u64),
            false,
        );
        let budget = Budget::default();
        let mut transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        transaction.push(&gzip).unwrap();
        let result = transaction.finish(false);
        assert!(!result.changed);
        assert_eq!(result.body.as_ref(), gzip);
    }
}
