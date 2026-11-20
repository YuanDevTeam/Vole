//! Pure-memory ownership regressions; actual anonymous maps, no peers.
use super::*;

fn mapped(budget: &Budget, capacity: usize) -> BudgetedBytes {
    let reservation = budget
        .reserve(BudgetedBytes::allocation_cost(capacity).unwrap())
        .unwrap();
    let output = BudgetedBytes::from_reserved_fixed_output(reservation, capacity).unwrap();
    assert!(output.is_mapped_for_test());
    output
}

fn observe_after_unmap(output: &mut BudgetedBytes) -> Arc<AtomicUsize> {
    let observed_used = Arc::new(AtomicUsize::new(usize::MAX));
    let Backing::Mapped(backing) = &mut output.bytes else {
        panic!("expected a real anonymous mapping");
    };
    backing.after_unmap = Some(MappedDropWitness {
        budget: output._reservation.budget.clone(),
        observed_used: observed_used.clone(),
    });
    observed_used
}

#[test]
fn mapped_output_keeps_requested_capacity_and_unmaps_before_final_refund() {
    let budget = Budget::default();
    // Non-page-multiple capacity exercises logical length separately from OS
    // page rounding; the latter is not charged as logical body payload.
    let capacity = MAPPED_FIXED_OUTPUT_MINIMUM + 3;
    let mut output = mapped(&budget, capacity);
    let cost = BudgetedBytes::allocation_cost(capacity).unwrap();
    assert_eq!(budget.used(), cost);
    assert_eq!(output.remaining(), capacity);
    assert!(output.as_ref().is_empty());
    let observed = observe_after_unmap(&mut output);
    output
        .write_initialized_output(capacity, |bytes| {
            assert_eq!(bytes.len(), capacity);
            assert!(bytes.iter().all(|byte| *byte == 0));
            bytes[..4].copy_from_slice(b"body");
            bytes[capacity - 1] = b'z';
            Ok(4)
        })
        .unwrap();
    assert_eq!(output.as_ref(), b"body");
    assert_eq!(output.remaining(), capacity - 4);
    let bytes = output.into_bytes();
    let cloned = bytes.clone();
    let tail = bytes.slice(1..3);
    drop(bytes);
    drop(cloned);
    assert_eq!(&tail[..], b"od");
    assert_eq!(budget.used(), cost);
    assert_eq!(observed.load(Ordering::Acquire), usize::MAX);
    drop(tail);
    // The witness runs after MmapMut's real destructor and still observes the
    // paid reservation; it does not claim a successful OS unmap or RSS change.
    assert_eq!(observed.load(Ordering::Acquire), cost);
    assert_eq!(budget.used(), 0);
}

#[test]
fn mapped_output_error_and_invalid_retained_length_expose_no_scratch() {
    let budget = Budget::default();
    let mut output = mapped(&budget, MAPPED_FIXED_OUTPUT_MINIMUM);
    let cost = budget.used();
    assert_eq!(
        output
            .write_initialized_output(5, |bytes| {
                bytes.copy_from_slice(b"stale");
                Err(io::ErrorKind::Interrupted.into())
            })
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert!(output.as_ref().is_empty());
    assert_eq!(output.remaining(), MAPPED_FIXED_OUTPUT_MINIMUM);
    assert_eq!(budget.used(), cost);
    assert!(
        output
            .write_initialized_output(5, |bytes| {
                assert_eq!(bytes, &[0; 5]);
                bytes.copy_from_slice(b"again");
                Ok(6)
            })
            .is_err()
    );
    assert!(output.as_ref().is_empty());
    assert_eq!(budget.used(), cost);
    output.extend(b"kept").unwrap();
    assert!(
        output
            .write_initialized_output(0, |_| panic!("nonempty output entered fill"))
            .is_err()
    );
    assert_eq!(output.as_ref(), b"kept");
    assert_eq!(budget.used(), cost);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[test]
fn mapped_output_map_failure_reuses_the_same_full_ledger_for_vec() {
    let budget = Budget::default();
    let capacity = MAPPED_FIXED_OUTPUT_MINIMUM;
    let cost = BudgetedBytes::allocation_cost(capacity).unwrap();
    let reservation = budget.reserve(cost).unwrap();
    let held = budget.reserve(WORKSPACE - cost).unwrap();
    let mut output = BudgetedBytes::from_reserved_fixed_output_with(
        reservation,
        capacity,
        |requested| {
            assert_eq!(requested, capacity);
            assert_eq!(budget.used(), WORKSPACE);
            Err(io::ErrorKind::OutOfMemory.into())
        },
        |requested| {
            // A second reserve would fail here; fallback must use the original
            // reservation while performing the real Vec allocation.
            assert_eq!(budget.used(), WORKSPACE);
            BudgetedBytes::allocate_vector(requested)
        },
    )
    .unwrap();
    assert!(!output.is_mapped_for_test());
    assert_eq!(output.remaining(), capacity);
    output
        .write_initialized_output(capacity, |bytes| {
            bytes.fill(b'z');
            bytes[..8].copy_from_slice(b"fallback");
            Ok(capacity)
        })
        .unwrap();
    assert_eq!(&output.as_ref()[..8], b"fallback");
    assert!(output.as_ref()[8..].iter().all(|byte| *byte == b'z'));
    assert_eq!(budget.used(), WORKSPACE);
    let sender = output.into_bytes();
    let last_slice = sender.slice(capacity - 1..);
    drop(sender);
    assert_eq!(last_slice.as_ref(), b"z");
    assert_eq!(budget.used(), WORKSPACE);
    drop(last_slice);
    assert_eq!(budget.used(), WORKSPACE - cost);
    drop(held);
    assert_eq!(budget.used(), 0);
}

#[test]
fn mapped_output_double_allocation_failure_and_bad_reservation_refund_once() {
    let budget = Budget::default();
    let capacity = MAPPED_FIXED_OUTPUT_MINIMUM;
    let cost = BudgetedBytes::allocation_cost(capacity).unwrap();
    let reservation = budget.reserve(cost).unwrap();
    assert!(
        BudgetedBytes::from_reserved_fixed_output_with(
            reservation,
            capacity,
            |_| {
                assert_eq!(budget.used(), cost);
                Err(io::ErrorKind::OutOfMemory.into())
            },
            |_| {
                assert_eq!(budget.used(), cost);
                None
            },
        )
        .is_none()
    );
    assert_eq!(budget.used(), 0);
    let short = budget.reserve(cost - 1).unwrap();
    assert!(
        BudgetedBytes::from_reserved_fixed_output_with(
            short,
            capacity,
            |_| panic!("invalid reservation reached mmap"),
            |_| panic!("invalid reservation reached Vec allocation"),
        )
        .is_none()
    );
    assert_eq!(budget.used(), 0);
}

#[test]
fn mapped_output_never_allocates_an_unpaid_string_copy() {
    let budget = Budget::default();
    let mut output = mapped(&budget, MAPPED_FIXED_OUTPUT_MINIMUM);
    let cost = budget.used();
    assert_eq!(
        output
            .write_text(|_| panic!("direct output entered String operation"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(output.as_ref().is_empty());
    assert_eq!(budget.used(), cost);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[forbid(unsafe_code)]
mod collector_fallback_extend_tests {
    use super::*;
    include!("shared_collector_fallback_extend_memory_test.rs");
}
