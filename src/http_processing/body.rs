//! Bounded, atomic content rewriting. Adapters retain their framing cursors.
use super::body_budget as budget;
#[path = "body_codec.rs"]
mod codec;
#[path = "body_json.rs"]
mod json;
pub(crate) use budget::{Budget, BudgetedBytes, MAX_BODY};

use super::{
    diagnostics::{self, BodyPoint, Counter},
    headers::Fields,
    rules::{BodyOperation, Phase, Rule, RuleAction},
};
use bytes::Bytes;
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
            identity_allowed: identity_allowed(fields),
        }
    }
}

pub(crate) struct WireBodyMeta {
    pub(crate) encoding: Encoding,
    pub(crate) length: Option<u64>,
    bypass: Option<Bypass>,
    text_bypass: Option<Bypass>,
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
        let mut text_bypass = None;
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
        for content_type in values("content-type") {
            let mut parts = content_type.split(';');
            let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            if media == "text/event-stream"
                || media == "application/grpc"
                || media.starts_with("application/grpc+")
                || media.starts_with("multipart/")
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
                    text_bypass = Some(Bypass::Charset);
                }
            }
        }
        if values("content-type").count() > 1 {
            text_bypass = Some(Bypass::Charset);
        }
        Self {
            encoding,
            length,
            bypass,
            text_bypass,
        }
    }
    pub(crate) fn eligibility(&self) -> Result<(), Bypass> {
        self.common_eligibility()?;
        if let Some(reason) = self.text_bypass {
            return Err(reason);
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

fn identity_allowed(fields: &Fields) -> bool {
    let mut identity = None;
    let mut wildcard = None;
    for (_, value) in fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
    {
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

pub(crate) fn has_rules(rules: &[Rule], original: &Url, phase: Phase) -> bool {
    rules.iter().any(|rule| {
        matches!(&rule.action, RuleAction::Body { phase: p, operation } if *p == phase && !matches!(operation, BodyOperation::JsonPatch(patch) if patch.is_empty()))
            && rule.matches(original)
    })
}

pub(crate) struct Transaction<'a> {
    budget: Budget,
    raw: BudgetedBytes,
    rules: &'a [Rule],
    original: &'a Url,
    phase: Phase,
    encoding: Encoding,
    text_allowed: bool,
}
pub(crate) struct ResultBody {
    pub(crate) body: BudgetedBytes,
    pub(crate) changed: bool,
    pub(crate) bypass: Option<Bypass>,
    original: Option<BudgetedBytes>,
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
        repair_metadata(&mut candidate, self.body.as_ref().len());
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
        original: &'a Url,
        phase: Phase,
        wire: &WireBodyMeta,
    ) -> Result<Self, Bypass> {
        diagnostics::increment(Counter::CollectorNativeRequested);
        let result = (|| {
            if !has_rules(rules, original, phase) {
                return Err(Bypass::NoRules);
            }
            wire.eligibility()?;
            let capacity = wire.length.map_or(MAX_BODY + 1, |length| length as usize);
            let raw = BudgetedBytes::new(budget, capacity).ok_or(Bypass::Budget)?;
            Ok(Self {
                budget: budget.clone(),
                raw,
                rules,
                original,
                phase,
                encoding: wire.encoding,
                text_allowed: true,
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
        original: &'a Url,
        phase: Phase,
        wire: &WireBodyMeta,
        script_body: bool,
    ) -> Result<Self, Bypass> {
        diagnostics::increment(Counter::CollectorSharedRequested);
        let result = (|| {
            if !script_body && !has_rules(rules, original, phase) {
                return Err(Bypass::NoRules);
            }
            if script_body {
                wire.common_eligibility()?;
            } else {
                wire.eligibility()?;
            }
            let capacity = wire.length.map_or(MAX_BODY + 1, |length| length as usize);
            Ok(Self {
                budget: budget.clone(),
                raw: BudgetedBytes::new(budget, capacity).ok_or(Bypass::Budget)?,
                rules,
                original,
                phase,
                encoding: wire.encoding,
                text_allowed: wire.eligibility().is_ok(),
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
        if std::str::from_utf8(baseline).is_err() {
            return fallback(self.raw, Bypass::InvalidText, BodyPoint::NativeDecode);
        }
        let candidate = match apply_operations(
            self.rules,
            self.original,
            self.phase,
            baseline,
            &self.budget,
        ) {
            Ok(candidate) => candidate,
            Err(reason) => {
                return ResultBody {
                    body: self.raw,
                    changed: false,
                    bypass: Some(reason),
                    original: None,
                };
            }
        };
        match candidate {
            Some(output) if output.as_ref() != baseline => ResultBody {
                body: output,
                changed: true,
                bypass: None,
                original: Some(self.raw),
            },
            _ => ResultBody {
                body: self.raw,
                changed: false,
                bypass: None,
                original: None,
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
                bypass: None,
                changed: false,
                original_text: self.text_allowed,
            },
            Err(reason) => {
                diagnostics::body_bypass(BodyPoint::SharedDecode, reason);
                return Entity {
                    wire,
                    logical: None,
                    bypass: Some(reason),
                    changed: false,
                    original_text: self.text_allowed,
                };
            }
        };
        if !has_rules(self.rules, self.original, self.phase) {
            return entity;
        }
        let baseline = entity.logical().expect("decoded entity");
        if !self.text_allowed || std::str::from_utf8(baseline).is_err() {
            let reason = if self.text_allowed {
                Bypass::InvalidText
            } else {
                Bypass::Charset
            };
            diagnostics::body_bypass(BodyPoint::NativeTransform, reason);
            entity.bypass = Some(reason);
            return entity;
        }
        match apply_operations(
            self.rules,
            self.original,
            self.phase,
            baseline,
            &self.budget,
        ) {
            Ok(Some(output)) if output.as_ref() != baseline => {
                let mut candidate = fields.clone();
                repair_metadata(&mut candidate, output.as_ref().len());
                if super::headers::check(&candidate).is_ok() {
                    *fields = candidate;
                    entity.replace(output.into_bytes());
                } else {
                    diagnostics::body_bypass(BodyPoint::HeaderFinalize, Bypass::Budget);
                    entity.bypass = Some(Bypass::Budget);
                }
            }
            Ok(_) => {}
            Err(reason) => entity.bypass = Some(reason),
        }
        entity
    }
}

/// Complete wire representation and its decoded logical view. `Bytes` keeps
/// the original allocation's workspace permit through clones and send queues.
#[derive(Clone)]
pub(crate) struct Entity {
    wire: Bytes,
    logical: Option<Bytes>,
    pub(crate) bypass: Option<Bypass>,
    changed: bool,
    original_text: bool,
}
impl Entity {
    #[cfg(test)]
    pub(crate) fn identity(bytes: BudgetedBytes) -> Self {
        let wire = bytes.into_bytes();
        Self {
            logical: Some(wire.clone()),
            wire,
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
    pub(crate) fn into_wire(self) -> Bytes {
        self.wire
    }
    pub(crate) fn changed(&self) -> bool {
        self.changed
    }
    pub(crate) fn original_text_allowed(&self) -> bool {
        self.original_text
    }
    pub(crate) fn replace(&mut self, bytes: Bytes) {
        self.wire = bytes.clone();
        self.logical = Some(bytes);
        self.bypass = None;
        self.changed = true;
    }
}

fn apply_operations(
    rules: &[Rule],
    original: &Url,
    phase: Phase,
    baseline: &[u8],
    budget: &Budget,
) -> Result<Option<BudgetedBytes>, Bypass> {
    diagnostics::increment(Counter::NativeTransformRequested);
    let result = (|| {
        let mut candidate = None;
        for rule in rules {
            let RuleAction::Body {
                phase: rule_phase,
                operation,
            } = &rule.action
            else {
                continue;
            };
            if *rule_phase != phase || !rule.matches(original) {
                continue;
            }
            match operation {
                BodyOperation::Set(value) => {
                    candidate =
                        Some(BudgetedBytes::copy(budget, value.as_bytes()).ok_or(Bypass::Budget)?);
                }
                BodyOperation::Replace(search) => {
                    let input = candidate
                        .as_ref()
                        .map_or(baseline, |value: &BudgetedBytes| value.as_ref());
                    let input = std::str::from_utf8(input).map_err(|_| Bypass::InvalidText)?;
                    let capacity = search.output_capacity(input.len(), MAX_BODY);
                    let mut output = BudgetedBytes::new(budget, capacity).ok_or(Bypass::Budget)?;
                    output
                        .write_text(|output| search.apply_into(input, output, MAX_BODY))
                        .map_err(|_| Bypass::Transform)?;
                    candidate = Some(output);
                }
                BodyOperation::JsonPatch(patch) if patch.is_empty() => {}
                BodyOperation::JsonPatch(patch) => {
                    let input = candidate
                        .as_ref()
                        .map_or(baseline, |value: &BudgetedBytes| value.as_ref());
                    let input = std::str::from_utf8(input).map_err(|_| Bypass::InvalidText)?;
                    candidate = Some(json::apply(input, patch, budget)?);
                }
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

/// Final representation repair follows successful content changes and therefore
/// takes precedence over independently successful ordinary header actions.
pub(crate) fn repair_metadata(fields: &mut Fields, length: usize) {
    repair_metadata_kind(fields, length, true);
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_capacity_uses_real_input_sized_allocations_for_every_literal_shape() {
        let url = Url::parse("http://capacity.example/").unwrap();
        for (input, search, replacement, occurrences, expected) in [
            ("aaaaa", "aa", "a", "first", "aaaa"),
            ("aaaaa", "aa", "a", "all", "aaa"),
            ("no match", "xx", "y", "all", "no match"),
            ("é中é", "é", "ø", "all", "ø中ø"),
            ("😀x😀", "😀", "é", "all", "éxé"),
            ("é中é", "é", "ab", "all", "ab中ab"),
            ("a$a", "a", "$", "all", "$$$"),
            ("$1-$1", "$1", "$", "all", "$-$"),
            ("aa-aa", "aa", "$1", "all", "$1-$1"),
            ("\0a\0", "\0", "x", "all", "xax"),
            ("", "a", "b", "all", ""),
        ] {
            let yaml = format!(
                "- {{url: '.', action: request-body-replace, search: {}, replacement: {}, occurrences: {occurrences}}}",
                serde_json::to_string(search).unwrap(),
                serde_json::to_string(replacement).unwrap()
            );
            let rules = rules(&yaml);
            let budget = Budget::default();
            let output = apply_operations(&rules, &url, Phase::Request, input.as_bytes(), &budget)
                .unwrap()
                .unwrap();
            assert_eq!(output.as_ref(), expected.as_bytes());
            // Tests both the live allocation and its admission. Refunding part
            // of a MAX allocation without freeing it cannot satisfy this.
            assert_eq!(output.remaining() + output.as_ref().len(), input.len());
            assert_eq!(
                budget.used(),
                BudgetedBytes::allocation_cost(input.len()).unwrap()
            );
            drop(output);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn literal_capacity_native_64k_owner_stays_charged_until_last_bytes_slice() {
        let budget = Budget::default();
        let rules = rules("- {url: '.', action: response-body-replace, search: q, replacement: z}");
        let url = Url::parse("http://capacity.example/").unwrap();
        let request = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(
            &vec![],
            &request,
            Phase::Response,
            Some(200),
            Some(65536),
            false,
        );
        let mut transaction =
            Transaction::begin_shared(&budget, &rules, &url, Phase::Response, &wire, true).unwrap();
        transaction.push(&vec![b'q'; 65536]).unwrap();
        let entity = transaction.finish_shared(false, &mut vec![]);
        assert!(entity.changed());
        assert_eq!(entity.bypass, None);
        assert_eq!(entity.logical().unwrap(), vec![b'z'; 65536]);
        let cost = BudgetedBytes::allocation_cost(65536).unwrap();
        assert_eq!(budget.used(), cost);
        let wire = entity.into_wire();
        let last_owner = wire.slice(17..);
        drop(wire);
        assert_eq!(budget.used(), cost);
        assert_eq!(last_owner.len(), 65536 - 17);
        drop(last_owner);
        assert_eq!(budget.used(), 0);
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
            let output = apply_operations(&rules, &url, Phase::Request, b"a", &budget)
                .unwrap()
                .unwrap();
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
    fn literal_capacity_keeps_phase_limit_and_whole_failed_native_stage_rollback() {
        let url = Url::parse("http://capacity.example/").unwrap();
        let request = OriginalRequestMeta::new("POST", &vec![]);
        let budget = Budget::default();
        let selected = rules(
            r#"
- {url: '.', action: request-body-replace, search: a, replacement: b}
- {url: '.', action: request-body-json-patch, patch: [{op: test, path: /ok, value: false}]}
"#,
        );
        let original = br#"{"ok":true,"v":"aaaa"}"#;
        let wire = WireBodyMeta::new(
            &vec![],
            &request,
            Phase::Request,
            None,
            Some(original.len() as u64),
            false,
        );
        let mut transaction =
            Transaction::begin_shared(&budget, &selected, &url, Phase::Request, &wire, true)
                .unwrap();
        transaction.push(original).unwrap();
        let mut fields = vec![
            ("X-Independent".into(), "kept".into()),
            ("ETag".into(), "old".into()),
        ];
        let expected_fields = fields.clone();
        let entity = transaction.finish_shared(false, &mut fields);
        assert!(!entity.changed());
        assert_eq!(entity.bypass, Some(Bypass::Transform));
        assert_eq!(entity.logical().unwrap(), original);
        assert_eq!(entity.wire().as_ref(), original);
        assert_eq!(fields, expected_fields);
        drop(entity);
        assert_eq!(budget.used(), 0);

        let growing =
            rules("- {url: '.', action: request-body-replace, search: a, replacement: aa}");
        let wire = WireBodyMeta::new(
            &vec![],
            &request,
            Phase::Request,
            None,
            Some(MAX_BODY as u64),
            false,
        );
        let mut transaction =
            Transaction::begin_shared(&budget, &growing, &url, Phase::Request, &wire, true)
                .unwrap();
        transaction.push(&vec![b'a'; MAX_BODY]).unwrap();
        let entity = transaction.finish_shared(false, &mut vec![]);
        assert!(!entity.changed());
        assert_eq!(entity.bypass, Some(Bypass::Transform));
        assert_eq!(entity.wire().len(), MAX_BODY);
        assert!(entity.wire().iter().all(|byte| *byte == b'a'));
        drop(entity);
        assert_eq!(budget.used(), 0);
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
