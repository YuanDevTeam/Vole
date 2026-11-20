// Tests only: the real Transaction::begin_shared selector and original ledger.
use super::*;

fn shared_selector_meta(length: Option<u64>, fields: &Fields) -> WireBodyMeta {
    let meta = OriginalRequestMeta::new("POST", fields);
    WireBodyMeta::new(fields, &meta, Phase::Request, None, length, false)
}

#[test]
fn shared_collector_known_boundaries_keep_one_paid_raw_owner() {
    let url = Url::parse("https://shared-collector.invalid/body").unwrap();
    let native = rules("- {url: '.', action: request-body-replace, search: a, replacement: a}");
    for length in [65535, 65536, 65537, MAX_BODY] {
        for script_body in [false, true] {
            let budget = Budget::default();
            let fields = vec![("Content-Type".into(), "text/plain; charset=utf-8".into())];
            let wire = shared_selector_meta(Some(length as u64), &fields);
            let cost = BudgetedBytes::allocation_cost(length).unwrap();
            let held = budget.reserve(budget::WORKSPACE - cost).unwrap();
            let selected = if script_body {
                &[][..]
            } else {
                native.as_slice()
            };
            let mut transaction = Transaction::begin_shared(
                &budget,
                selected,
                &url,
                Phase::Request,
                &wire,
                script_body,
            )
            .unwrap();
            assert_eq!(budget.used(), budget::WORKSPACE);
            assert!(transaction.raw.budget().same_ledger(&budget));
            assert!(transaction.raw.as_ref().is_empty());
            assert_eq!(transaction.remaining(), length);
            if !cfg!(target_vendor = "apple") || length < 65536 {
                assert!(!transaction.raw.is_mapped_for_test());
            }
            assert!(matches!(
                Transaction::begin_shared(
                    &budget,
                    selected,
                    &url,
                    Phase::Request,
                    &wire,
                    script_body,
                ),
                Err(Bypass::Budget)
            ));
            let mut input = vec![b'a'; length];
            let suffix = "é😀中\0$".as_bytes();
            input[length - suffix.len()..].copy_from_slice(suffix);
            let mut collected = 0;
            for chunk in input.chunks(4093) {
                transaction.push(chunk).unwrap();
                collected += chunk.len();
                assert_eq!(transaction.raw.as_ref(), &input[..collected]);
                assert_eq!(transaction.remaining(), length - collected);
                assert_eq!(budget.used(), budget::WORKSPACE);
            }
            let bytes = transaction.into_raw().into_bytes();
            assert_eq!(bytes.as_ref(), input);
            let clone = bytes.clone();
            let slice = bytes.slice(length - suffix.len()..);
            drop(bytes);
            drop(clone);
            drop(held);
            assert_eq!(slice.as_ref(), suffix);
            assert_eq!(budget.used(), cost);
            drop(slice);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[cfg(target_vendor = "apple")]
#[test]
#[ignore = "physical Apple map fixture only; legal mmap fallback is not a semantic failure"]
fn apple_shared_collector_mapping_path_fixture() {
    let url = Url::parse("https://shared-collector.invalid/body").unwrap();
    let native = rules("- {url: '.', action: request-body-replace, search: a, replacement: a}");
    for length in [65536, 65537, MAX_BODY] {
        for script_body in [false, true] {
            let budget = Budget::default();
            let control = BudgetedBytes::new_fixed_output(&budget, length).unwrap();
            assert!(
                control.is_mapped_for_test(),
                "physical map fixture unavailable"
            );
            drop(control);
            let wire = shared_selector_meta(Some(length as u64), &vec![]);
            let selected = if script_body {
                &[][..]
            } else {
                native.as_slice()
            };
            let transaction = Transaction::begin_shared(
                &budget,
                selected,
                &url,
                Phase::Request,
                &wire,
                script_body,
            )
            .unwrap();
            let raw = transaction.into_raw();
            let actual = raw.is_mapped_for_test();
            drop(raw);
            assert_eq!(budget.used(), 0);
            // Failure is meaningful only after the owner confirms mmap did
            // not legitimately fail between the control and selector calls.
            assert!(
                actual,
                "shared selector unmapped: inspect legal fallback vs old wiring"
            );
        }
    }
}

#[test]
fn shared_unknown_sentinel_and_native_entry_keep_vector_and_original_limit() {
    let budget = Budget::default();
    let url = Url::parse("https://shared-collector.invalid/body").unwrap();
    let native = rules("- {url: '.', action: request-body-replace, search: a, replacement: a}");
    let wire = shared_selector_meta(Some(65536), &vec![]);
    let native_only = Transaction::begin(&budget, &native, &url, Phase::Request, &wire).unwrap();
    assert!(!native_only.raw.is_mapped_for_test());
    drop(native_only);
    let unknown = shared_selector_meta(None, &vec![]);
    let mut transaction =
        Transaction::begin_shared(&budget, &[], &url, Phase::Request, &unknown, true).unwrap();
    assert!(!transaction.raw.is_mapped_for_test());
    assert_eq!(transaction.remaining(), MAX_BODY + 1);
    let cost = BudgetedBytes::allocation_cost(MAX_BODY + 1).unwrap();
    assert_eq!(budget.used(), cost);
    assert_eq!(
        transaction.push(&vec![b'a'; MAX_BODY + 1]),
        Err(Bypass::Size)
    );
    let raw = transaction.into_raw();
    assert_eq!(raw.as_ref().len(), MAX_BODY + 1);
    assert_eq!(raw.remaining(), 0);
    assert!(!raw.is_mapped_for_test());
    drop(raw);
    let oversized = shared_selector_meta(Some(MAX_BODY as u64 + 1), &vec![]);
    assert!(matches!(
        Transaction::begin_shared(&budget, &[], &url, Phase::Request, &oversized, true),
        Err(Bypass::Size)
    ));
    assert!(matches!(
        Transaction::begin_shared(&budget, &[], &url, Phase::Request, &wire, false),
        Err(Bypass::NoRules)
    ));
    assert_eq!(budget.used(), 0);
}

#[test]
fn large_shared_native_failure_and_header_failure_keep_original_raw() {
    let original = vec![b'a'; 65536];
    let url = Url::parse("https://shared-collector.invalid/body").unwrap();
    for header_failure in [false, true] {
        let selected = rules(if header_failure {
            "- {url: '.', action: request-body-replace, search: a, replacement: b}"
        } else {
            "- {url: '.', action: request-body-replace, search: a, replacement: b}\n- {url: '.', action: request-body-json-patch, patch: [{op: test, path: /ok, value: false}]}"
        });
        let budget = Budget::default();
        let mut fields: Fields = vec![
            ("Content-Length".into(), "65536".into()),
            ("Content-Type".into(), "text/plain".into()),
            ("X-Independent".into(), "kept".into()),
        ];
        if header_failure {
            let used = fields
                .iter()
                .map(|(n, v)| n.len() + v.len() + 32)
                .sum::<usize>();
            fields.push((
                "X-Pad".into(),
                "p".repeat(crate::http_processing::headers::MAX_BYTES - used - 5 - 32),
            ));
        }
        crate::http_processing::headers::check(&fields).unwrap();
        let before = fields.clone();
        let wire = shared_selector_meta(Some(original.len() as u64), &fields);
        // false represents a native body plus metadata-only JS shared caller.
        let mut transaction =
            Transaction::begin_shared(&budget, &selected, &url, Phase::Request, &wire, false)
                .unwrap();
        transaction.push(&original).unwrap();
        let source_pointer = transaction.raw.as_ref().as_ptr();
        let entity = transaction.finish_shared(false, &mut fields);
        assert!(!entity.changed());
        assert_eq!(
            entity.bypass,
            Some(if header_failure {
                Bypass::Budget
            } else {
                Bypass::Transform
            })
        );
        assert_eq!(entity.wire().as_ptr(), source_pointer);
        assert_eq!(entity.logical().unwrap(), original);
        assert_eq!(fields, before);
        let last = entity.wire().slice(65535..);
        drop(entity);
        assert_eq!(last.as_ref(), b"a");
        assert_eq!(
            budget.used(),
            BudgetedBytes::allocation_cost(65536).unwrap()
        );
        drop(last);
        assert_eq!(budget.used(), 0);
    }
}
