// Same physical allocator seam, but the real collector byte-extension API.
#[test]
fn mapped_fallback_collector_extend_keeps_reservation_and_final_slice() {
    let budget = Budget::default();
    let capacity = MAPPED_FIXED_OUTPUT_MINIMUM + 3;
    let cost = BudgetedBytes::allocation_cost(capacity).unwrap();
    let reservation = budget.reserve(cost).unwrap();
    let held = budget.reserve(WORKSPACE - cost).unwrap();
    let mut raw = BudgetedBytes::from_reserved_fixed_output_with(
        reservation,
        capacity,
        |requested| {
            assert_eq!(requested, capacity);
            assert_eq!(budget.used(), WORKSPACE);
            Err(io::ErrorKind::OutOfMemory.into())
        },
        |requested| {
            assert_eq!(requested, capacity);
            assert_eq!(budget.used(), WORKSPACE);
            BudgetedBytes::allocate_vector(requested)
        },
    )
    .unwrap();
    assert!(!raw.is_mapped_for_test());
    assert!(raw.as_ref().is_empty());
    assert_eq!(raw.remaining(), capacity);
    let mut expected = vec![b'a'; capacity];
    expected[capacity - 5..].copy_from_slice(b"tail\0");
    let mut length = 0;
    for chunk in expected.chunks(1021) {
        raw.extend(chunk).unwrap();
        length += chunk.len();
        assert_eq!(raw.as_ref(), &expected[..length]);
        assert_eq!(raw.remaining(), capacity - length);
        assert_eq!(budget.used(), WORKSPACE);
    }
    assert!(raw.extend(b"x").is_err());
    assert_eq!(raw.as_ref(), expected);
    let bytes = raw.into_bytes();
    let clone = bytes.clone();
    let last = bytes.slice(capacity - 5..);
    drop(bytes);
    drop(clone);
    assert_eq!(budget.used(), WORKSPACE);
    drop(held);
    assert_eq!(last.as_ref(), b"tail\0");
    assert_eq!(budget.used(), cost);
    drop(last);
    assert_eq!(budget.used(), 0);
}
