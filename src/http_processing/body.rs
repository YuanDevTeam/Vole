//! Bounded, atomic content rewriting. Adapters retain their framing cursors.
use super::body_budget as budget;
#[path = "body_codec.rs"]
mod codec;
#[path = "body_json.rs"]
mod json;
pub(crate) use budget::{Budget, BudgetedBytes, MAX_BODY};

use super::{
    headers::Fields,
    rules::{BodyOperation, Phase, Rule, RuleAction},
};
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
        if original.head
            || original.connect
            || upgraded
            || status.is_some_and(|status| status < 200 || matches!(status, 204 | 304))
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
                    bypass = Some(Bypass::Charset);
                }
            }
        }
        if values("content-type").count() > 1 {
            bypass = Some(Bypass::Charset);
        }
        Self {
            encoding,
            length,
            bypass,
        }
    }
    pub(crate) fn eligibility(&self) -> Result<(), Bypass> {
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
}
pub(crate) struct ResultBody {
    pub(crate) body: BudgetedBytes,
    pub(crate) changed: bool,
    pub(crate) bypass: Option<Bypass>,
    original: Option<BudgetedBytes>,
}
impl ResultBody {
    pub(crate) fn rollback(&mut self, reason: Bypass) {
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
        })
    }
    pub(crate) fn remaining(&self) -> usize {
        self.raw.remaining()
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), Bypass> {
        self.raw.extend(bytes).map_err(|_| Bypass::Size)?;
        if self.raw.as_ref().len() > MAX_BODY {
            return Err(Bypass::Size);
        }
        Ok(())
    }
    pub(crate) fn into_raw(self) -> BudgetedBytes {
        self.raw
    }
    pub(crate) fn finish(self, has_trailers: bool) -> ResultBody {
        let fallback = |raw, reason| ResultBody {
            body: raw,
            changed: false,
            bypass: Some(reason),
            original: None,
        };
        if has_trailers {
            return fallback(self.raw, Bypass::Trailers);
        }
        if self.raw.as_ref().len() > MAX_BODY {
            return fallback(self.raw, Bypass::Size);
        }
        let decoded = match codec::decode(self.raw.as_ref(), self.encoding, &self.budget) {
            Ok(decoded) => decoded,
            Err(reason) => return fallback(self.raw, reason),
        };
        let baseline = decoded
            .as_ref()
            .map_or(self.raw.as_ref(), |value| value.as_ref());
        if std::str::from_utf8(baseline).is_err() {
            return fallback(self.raw, Bypass::InvalidText);
        }
        let mut candidate = None;
        for rule in self.rules {
            let RuleAction::Body { phase, operation } = &rule.action else {
                continue;
            };
            if *phase != self.phase || !rule.matches(self.original) {
                continue;
            }
            match operation {
                BodyOperation::Set(value) => {
                    let Some(output) = BudgetedBytes::copy(&self.budget, value.as_bytes()) else {
                        return fallback(self.raw, Bypass::Budget);
                    };
                    candidate = Some(output);
                }
                BodyOperation::Replace(search) => {
                    let input = candidate
                        .as_ref()
                        .map_or(baseline, |value: &BudgetedBytes| value.as_ref());
                    let input = std::str::from_utf8(input).expect("body candidates stay UTF-8");
                    let Some(mut output) = BudgetedBytes::new(&self.budget, MAX_BODY) else {
                        return fallback(self.raw, Bypass::Budget);
                    };
                    if output
                        .write_text(|output| search.apply_into(input, output, MAX_BODY))
                        .is_err()
                    {
                        return fallback(self.raw, Bypass::Transform);
                    }
                    candidate = Some(output);
                }
                BodyOperation::JsonPatch(patch) if patch.is_empty() => {}
                BodyOperation::JsonPatch(patch) => {
                    let input = candidate
                        .as_ref()
                        .map_or(baseline, |value: &BudgetedBytes| value.as_ref());
                    let input = std::str::from_utf8(input).expect("body candidates stay UTF-8");
                    match json::apply(input, patch, &self.budget) {
                        Ok(output) => candidate = Some(output),
                        Err(reason) => return fallback(self.raw, reason),
                    }
                }
            }
        }
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
}

/// Final representation repair follows successful content changes and therefore
/// takes precedence over independently successful ordinary header actions.
pub(crate) fn repair_metadata(fields: &mut Fields, length: usize) {
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
        )
    });
    for (name, value) in fields.iter_mut() {
        if name.eq_ignore_ascii_case("content-type") {
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
