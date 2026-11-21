//! Remove HTTP/3 alternatives from the final downstream response.
use super::Fields;
use http::{HeaderMap, HeaderValue, header::ALT_SVC};

pub(crate) fn filter_fields(fields: &mut Fields) {
    let mut changed = false;
    fields.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case("alt-svc")
            && let Some(filtered) = filter_value(value.as_bytes())
        {
            changed = true;
            if filtered.is_empty() {
                return false;
            }
            *value = String::from_utf8(filtered).expect("UTF-8 alternatives");
        }
        true
    });
    if changed
        && !fields
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("alt-svc"))
    {
        fields.push(("alt-svc".into(), "clear".into()));
    }
}

pub(in crate::http_processing) fn filter_map(headers: &mut HeaderMap) {
    let all = headers.get_all(ALT_SVC);
    let mut changed: Option<Vec<HeaderValue>> = None;
    for (index, value) in all.iter().enumerate() {
        if let Some(filtered) = filter_value(value.as_bytes()) {
            let kept = changed.get_or_insert_with(|| all.iter().take(index).cloned().collect());
            if !filtered.is_empty() {
                let mut replacement =
                    HeaderValue::from_bytes(&filtered).expect("valid alternative header bytes");
                replacement.set_sensitive(value.is_sensitive());
                kept.push(replacement);
            }
        } else if let Some(kept) = &mut changed {
            kept.push(value.clone());
        }
    }
    if let Some(kept) = changed {
        headers.remove(ALT_SVC);
        if kept.is_empty() {
            headers.insert(ALT_SVC, HeaderValue::from_static("clear"));
        } else {
            for value in kept {
                headers.append(ALT_SVC, value);
            }
        }
    }
}

/// RFC 7838 lists allow quoted commas in extension parameter values. Leave
/// ambiguous malformed fields unchanged. ALPN names are case sensitive.
fn filter_value(value: &[u8]) -> Option<Vec<u8>> {
    if !value.windows(2).any(|bytes| bytes == b"h3") {
        return None;
    }
    let mut inside_quote = false;
    let mut escaped = false;
    let mut kept = Vec::new();
    let mut removed = false;
    for alternative in value.split(|byte| {
        if escaped {
            escaped = false;
        } else if inside_quote && *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            inside_quote = !inside_quote;
        } else if !inside_quote && *byte == b',' {
            return true;
        }
        false
    }) {
        let alternative = alternative.trim_ascii();
        if alternative.is_empty() {
            continue;
        }
        let h3 = alternative
            .iter()
            .position(|byte| *byte == b'=')
            .is_some_and(|index| {
                let protocol = alternative[..index].trim_ascii_end();
                let target = alternative[index + 1..].trim_ascii_start();
                target.starts_with(b"\"")
                    && (protocol == b"h3"
                        || protocol.strip_prefix(b"h3-").is_some_and(|version| {
                            !version.is_empty() && version.iter().all(u8::is_ascii_digit)
                        }))
            });
        if h3 {
            removed = true;
        } else {
            if !kept.is_empty() {
                kept.push(b',');
            }
            kept.extend_from_slice(alternative);
        }
    }
    (removed && !inside_quote).then_some(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_svc_preserves_alternative_order_and_quoted_parameters() {
        let mut fields = vec![
            (
                "Alt-Svc".into(),
                "h3=\":443\"; ma=60, h2=\":444\"; ext=\"x,h3=\\\"y\\\"\"".into(),
            ),
            ("alt-svc".into(), "h3-29=\":443\", test=\":555\"".into()),
            ("Alt-Svc".into(), "H3=\":555\"; ma=2".into()),
        ];
        filter_fields(&mut fields);
        assert_eq!(
            fields,
            [
                (
                    "Alt-Svc".into(),
                    "h2=\":444\"; ext=\"x,h3=\\\"y\\\"\"".into()
                ),
                ("alt-svc".into(), "test=\":555\"".into()),
                ("Alt-Svc".into(), "H3=\":555\"; ma=2".into()),
            ]
        );
    }

    #[test]
    fn alt_svc_replaces_h3_only_fields_with_one_clear() {
        let mut headers = HeaderMap::new();
        headers.append(ALT_SVC, HeaderValue::from_static("h3=\":443\""));
        headers.append(ALT_SVC, HeaderValue::from_static("h3-29=\":8443\""));
        filter_map(&mut headers);
        assert_eq!(
            headers.get_all(ALT_SVC).iter().collect::<Vec<_>>(),
            ["clear"]
        );

        let mut fields = vec![("Alt-Svc".into(), "h3=\":443\"".into())];
        filter_fields(&mut fields);
        assert_eq!(fields, [("alt-svc".into(), "clear".into())]);
    }

    #[test]
    fn alt_svc_ignores_unknown_and_ambiguous_advertisements() {
        for value in [
            &b"h2=\":443\"; hint=\"h3\""[..],
            b"h3=\":443\", h2=\"unclear",
            b"h3-not-http=\":443\"",
            b"clear",
        ] {
            assert_eq!(filter_value(value), None);
        }
    }
}
