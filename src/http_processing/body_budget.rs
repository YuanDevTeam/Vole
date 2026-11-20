//! Runtime-wide, nonwaiting ownership of temporary HTTP body allocations.
use bytes::Bytes;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) const MAX_BODY: usize = 256 * 1024;
pub(crate) const WORKSPACE: usize = 4 * 1024 * 1024;

// A public JSC string view can own an N-byte 8-bit copy plus a 2N-byte
// UTF-16 expansion. This is bridge admission, not a VM heap bound.
#[cfg(feature = "inbound-http")]
pub(crate) const API_TEXT_VIEW: usize = 3 * MAX_BODY;

#[cfg(all(feature = "inbound-http", test))]
pub(crate) fn bridge_workspace_cost(input: usize, text: bool) -> Option<usize> {
    BridgePlan::new(input, text, MAX_BODY)?.cost()
}

// A paid API terminator scratch byte is never a larger logical body bound.
#[cfg(feature = "inbound-http")]
pub(crate) fn output_capacity(bound: usize) -> Option<usize> {
    if bound > MAX_BODY {
        return None;
    }
    Some(if bound > 0 && bound < MAX_BODY {
        bound + 1
    } else {
        bound
    })
}

/// Independent retained-input and scratch payloads. This is a conservative
/// copy ledger, not storage, a VM heap limit, or a second execution lane.
#[cfg(feature = "inbound-http")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BridgePlan {
    pub(crate) retained_input: usize,
    pub(crate) view_capacity: usize,
    pub(crate) input_vec_bookkeeping: usize,
}
#[cfg(feature = "inbound-http")]
impl BridgePlan {
    pub(crate) fn new(input: usize, text: bool, output: usize) -> Option<Self> {
        if input > MAX_BODY || output > MAX_BODY {
            return None;
        }
        let vector = std::mem::size_of::<Vec<u16>>();
        let literal_peak = input
            .checked_mul(7)?
            .checked_add(vector)?
            .min(API_TEXT_VIEW);
        let view_capacity = output.checked_mul(3)?.max(literal_peak);
        Some(Self {
            retained_input: if text { input.checked_mul(2)? } else { 0 },
            view_capacity,
            input_vec_bookkeeping: if text { vector } else { 0 },
        })
    }
    pub(crate) fn cost(self) -> Option<usize> {
        self.retained_input
            .checked_add(self.view_capacity)?
            .checked_add(self.input_vec_bookkeeping)
    }
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    pub(crate) fn allows_utf8_input(self, input: usize) -> bool {
        input
            .checked_mul(3)
            .and_then(|n| n.checked_add(1))
            .is_some_and(|peak| peak <= self.view_capacity)
    }
}

#[derive(Clone)]
pub(crate) struct Budget(Arc<Inner>);
struct Inner {
    used: AtomicUsize,
    limit: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self(Arc::new(Inner {
            used: AtomicUsize::new(0),
            limit: WORKSPACE,
        }))
    }
}

impl Budget {
    /// Identity of the actual shared ledger, independent of its current charge.
    pub(super) fn same_ledger(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn reserve(&self, bytes: usize) -> Option<Reservation> {
        let previous = match self
            .0
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.0.limit)
            }) {
            Ok(previous) => previous,
            Err(_) => {
                super::diagnostics::increment(super::diagnostics::Counter::BodyReserveRejected);
                return None;
            }
        };
        super::diagnostics::body_reserved(bytes, previous + bytes);
        Some(Reservation {
            budget: self.clone(),
            bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.0.used.load(Ordering::Acquire)
    }
}

pub(crate) struct Reservation {
    budget: Budget,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.bytes, Ordering::AcqRel);
        super::diagnostics::body_released(self.bytes);
    }
}

impl Reservation {
    /// Join reservations from one ledger without changing its admitted total.
    /// Failure preserves the additional owner; no amount is silently refunded.
    #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
    pub(crate) fn merge(&mut self, mut additional: Self) -> Result<(), Self> {
        if !Arc::ptr_eq(&self.budget.0, &additional.budget.0) {
            return Err(additional);
        }
        let Some(bytes) = self.bytes.checked_add(additional.bytes) else {
            return Err(additional);
        };
        self.bytes = bytes;
        additional.bytes = 0;
        Ok(())
    }

    #[cfg(feature = "inbound-http")]
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    pub(crate) fn covers(&self, output: &BudgetedBytes, bytes: usize) -> bool {
        self.bytes >= bytes && Arc::ptr_eq(&self.budget.0, &output._reservation.budget.0)
    }

    /// Divide an already admitted reservation without changing the shared total.
    pub(crate) fn split(&mut self, bytes: usize) -> Option<Self> {
        if bytes > self.bytes {
            return None;
        }
        self.bytes -= bytes;
        Some(Self {
            budget: self.budget.clone(),
            bytes,
        })
    }
}

/// A fixed-capacity allocation. Its reservation follows every Bytes slice and
/// is released only when the last sender/driver has dropped the actual owner.
pub(crate) struct BudgetedBytes {
    // Fields drop in declaration order. The real backing owner must finish its
    // destruction (including an anonymous map's unmap Drop) before refunding.
    bytes: Backing,
    _reservation: Reservation,
}

enum Backing {
    Vector(Vec<u8>),
    #[cfg(all(unix, feature = "inbound-http"))]
    Mapped(MappedOutput),
}

#[cfg(all(unix, feature = "inbound-http"))]
const MAPPED_FIXED_OUTPUT_MINIMUM: usize = 64 * 1024;

#[cfg(all(unix, feature = "inbound-http"))]
struct MappedOutput {
    bytes: memmap2::MmapMut,
    length: usize,
    // Test-only observation runs after the real mapping destructor, before
    // BudgetedBytes refunds. It does not assert OS unmap success or RSS.
    #[cfg(test)]
    after_unmap: Option<MappedDropWitness>,
}

#[cfg(all(test, unix, feature = "inbound-http"))]
struct MappedDropWitness {
    budget: Budget,
    observed_used: Arc<AtomicUsize>,
}

#[cfg(all(test, unix, feature = "inbound-http"))]
impl Drop for MappedDropWitness {
    fn drop(&mut self) {
        self.observed_used
            .store(self.budget.used(), Ordering::Release);
    }
}

impl Backing {
    fn capacity(&self) -> usize {
        match self {
            Self::Vector(bytes) => bytes.capacity(),
            #[cfg(all(unix, feature = "inbound-http"))]
            Self::Mapped(mapped) => mapped.bytes.len(),
        }
    }

    fn initialized(&mut self, length: usize) -> &mut [u8] {
        match self {
            Self::Vector(bytes) => {
                bytes.resize(length, 0);
                bytes
            }
            #[cfg(all(unix, feature = "inbound-http"))]
            Self::Mapped(mapped) => {
                mapped.length = length;
                let bytes = &mut mapped.bytes[..length];
                // Match Vec::resize even when an earlier failed callback left
                // scratch contents in this still-owned, fully paid mapping.
                bytes.fill(0);
                bytes
            }
        }
    }

    fn truncate(&mut self, length: usize) {
        match self {
            Self::Vector(bytes) => bytes.truncate(length),
            #[cfg(all(unix, feature = "inbound-http"))]
            Self::Mapped(mapped) => mapped.length = mapped.length.min(length),
        }
    }
}

impl AsRef<[u8]> for Backing {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Vector(bytes) => bytes,
            #[cfg(all(unix, feature = "inbound-http"))]
            Self::Mapped(mapped) => &mapped.bytes[..mapped.length],
        }
    }
}

impl BudgetedBytes {
    /// The allocation's actual ledger; borrowing this handle does not refund it.
    pub(crate) fn budget(&self) -> &Budget {
        &self._reservation.budget
    }

    #[cfg(feature = "inbound-http")]
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    pub(crate) fn reserve_temporary(&self, bytes: usize) -> Option<Reservation> {
        self._reservation.budget.reserve(bytes)
    }

    /// No allocation and no body-workspace admission for a metadata-only call.
    /// A backend exporting a nonempty result must call `prepare_output` first.
    pub(crate) fn empty(budget: &Budget) -> Self {
        Self {
            bytes: Backing::Vector(Vec::new()),
            _reservation: Reservation {
                budget: budget.clone(),
                bytes: 0,
            },
        }
    }
    pub(crate) fn allocation_cost(capacity: usize) -> Option<usize> {
        capacity.checked_add(std::mem::size_of::<Self>())
    }

    pub(crate) fn new(budget: &Budget, capacity: usize) -> Option<Self> {
        let bytes = Self::allocation_cost(capacity)?;
        let reservation = budget.reserve(bytes)?;
        Self::from_reserved(reservation, capacity)
    }

    /// All known shared entities keep original one-shot admission/capacity.
    /// Apple may map them, also with native body plus metadata-only scripts.
    /// Unknown lengths keep the original MAX_BODY + 1 Vec sentinel.
    pub(crate) fn new_shared_collector(
        budget: &Budget,
        capacity: usize,
        known_length: bool,
    ) -> Option<Self> {
        let reservation = budget.reserve(Self::allocation_cost(capacity)?)?;
        if cfg!(target_vendor = "apple") && known_length && capacity <= MAX_BODY {
            Self::from_reserved_fixed_capacity(reservation, capacity)
        } else {
            Self::from_reserved(reservation, capacity)
        }
    }

    pub(crate) fn from_reserved(reservation: Reservation, capacity: usize) -> Option<Self> {
        if reservation.bytes != Self::allocation_cost(capacity)? {
            return None;
        }
        Some(Self {
            bytes: Backing::Vector(Self::allocate_vector(capacity)?),
            _reservation: reservation,
        })
    }

    fn allocate_vector(capacity: usize) -> Option<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(capacity).ok()?;
        // Vec's allocation policy is allowed to return more than requested.
        // Never silently retain an unreserved capacity.
        if buffer.capacity() > capacity {
            return None;
        }
        Some(buffer)
    }

    /// Independently admit a proven fixed-bound byte output before its fill.
    /// Closed Plans and native ASCII byte maps use this allocation policy.
    pub(crate) fn new_fixed_output(budget: &Budget, capacity: usize) -> Option<Self> {
        if capacity > MAX_BODY {
            return None;
        }
        let reservation = budget.reserve(Self::allocation_cost(capacity)?)?;
        Self::from_reserved_fixed_output(reservation, capacity)
    }

    /// Reuse a complete reservation for a proven fixed-bound byte output.
    /// Native String/JSC outputs and the separate native-only entry keep Vec.
    pub(crate) fn from_reserved_fixed_output(
        reservation: Reservation,
        capacity: usize,
    ) -> Option<Self> {
        Self::from_reserved_fixed_capacity(reservation, capacity)
    }

    // Physical fixed-capacity byte backing only: this does not initialize an
    // output, infer a body length, or create another workspace reservation.
    fn from_reserved_fixed_capacity(reservation: Reservation, capacity: usize) -> Option<Self> {
        if capacity > MAX_BODY {
            return None;
        }
        #[cfg(all(unix, feature = "inbound-http"))]
        {
            Self::from_reserved_fixed_output_with(
                reservation,
                capacity,
                memmap2::MmapMut::map_anon,
                Self::allocate_vector,
            )
        }
        #[cfg(not(all(unix, feature = "inbound-http")))]
        {
            Self::from_reserved(reservation, capacity)
        }
    }

    #[cfg(all(unix, feature = "inbound-http"))]
    fn from_reserved_fixed_output_with(
        reservation: Reservation,
        capacity: usize,
        map: impl FnOnce(usize) -> io::Result<memmap2::MmapMut>,
        vector: impl FnOnce(usize) -> Option<Vec<u8>>,
    ) -> Option<Self> {
        if capacity > MAX_BODY || reservation.bytes != Self::allocation_cost(capacity)? {
            return None;
        }
        let mapping = if capacity >= MAPPED_FIXED_OUTPUT_MINIMUM {
            map(capacity).ok().filter(|bytes| bytes.len() == capacity)
        } else {
            None
        };
        let bytes = if let Some(bytes) = mapping {
            Backing::Mapped(MappedOutput {
                bytes,
                length: 0,
                #[cfg(test)]
                after_unmap: None,
            })
        } else {
            // Mapping failure does not consume or reacquire the reservation.
            // Only one successful backing allocation is ever retained.
            let bytes = vector(capacity)?;
            if !bytes.is_empty() || bytes.capacity() != capacity {
                return None;
            }
            Backing::Vector(bytes)
        };
        Some(Self {
            bytes,
            _reservation: reservation,
        })
    }

    #[cfg(all(test, unix, feature = "inbound-http"))]
    pub(crate) fn is_mapped_for_test(&self) -> bool {
        matches!(self.bytes, Backing::Mapped(_))
    }

    /// Admit a known result before copying it out of an engine. Body-less calls
    /// use an empty buffer until the backend knows that a result has a body.
    #[cfg(all(feature = "inbound-http", any(test, target_vendor = "apple")))]
    pub(crate) fn prepare_output(&mut self, length: usize) -> io::Result<()> {
        if length > MAX_BODY {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP script body exceeded",
            ));
        }
        if self.bytes.capacity() >= length {
            return Ok(());
        }
        let replacement = Self::new(&self._reservation.budget, length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "HTTP body workspace exceeded")
        })?;
        if !self.bytes.as_ref().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP script output is not empty",
            ));
        }
        *self = replacement;
        Ok(())
    }

    pub(crate) fn copy(budget: &Budget, value: &[u8]) -> Option<Self> {
        let mut result = Self::new(budget, value.len())?;
        result.extend(value).ok()?;
        Some(result)
    }

    pub(crate) fn extend(&mut self, value: &[u8]) -> io::Result<()> {
        if value.len() > self.remaining() {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP body workspace exceeded",
            ));
        }
        match &mut self.bytes {
            Backing::Vector(bytes) => bytes.extend_from_slice(value),
            #[cfg(all(unix, feature = "inbound-http"))]
            Backing::Mapped(mapped) => {
                let end = mapped.length + value.len();
                mapped.bytes[mapped.length..end].copy_from_slice(value);
                mapped.length = end;
            }
        }
        Ok(())
    }

    /// Fill initialized bytes inside an existing, independently admitted allocation.
    /// The callback returns the retained length; scratch bytes remain charged
    /// through this owner's unchanged capacity and are never exposed as body.
    pub(crate) fn write_initialized_output(
        &mut self,
        length: usize,
        operation: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<()> {
        if !self.bytes.as_ref().is_empty() || length > MAX_BODY || length > self.remaining() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP script output scratch is not available",
            ));
        }
        // The capacity check above prevents resize from allocating. Every byte
        // passed to the callback is initialized, including terminator scratch.
        let result = operation(self.bytes.initialized(length));
        match result {
            Ok(retained) if retained <= length => {
                self.bytes.truncate(retained);
                Ok(())
            }
            Ok(_) => {
                self.bytes.truncate(0);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP script output scratch length is invalid",
                ))
            }
            Err(error) => {
                self.bytes.truncate(0);
                Err(error)
            }
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.capacity() - self.bytes.as_ref().len()
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }

    pub(crate) fn write_text(
        &mut self,
        operation: impl FnOnce(&mut String) -> io::Result<()>,
    ) -> io::Result<()> {
        // Mapped backing is private to bounded byte writers/collectors. Do not
        // silently allocate an unpaid String copy if that internal boundary is
        // accidentally crossed; all existing String-capable constructors use Vec.
        let bytes = match &mut self.bytes {
            Backing::Vector(bytes) => bytes,
            #[cfg(all(unix, feature = "inbound-http"))]
            Backing::Mapped(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HTTP direct output does not use String storage",
                ));
            }
        };
        let mut text = String::from_utf8(std::mem::take(bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP body text is invalid"))?;
        let result = operation(&mut text);
        *bytes = text.into_bytes();
        result
    }
}

impl AsRef<[u8]> for BudgetedBytes {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
impl io::Write for BudgetedBytes {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        self.extend(value)?;
        Ok(value.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "inbound-http")]
    #[test]
    fn bounded_bridge_plan_preserves_maximum_boundary_and_constructor_peaks() {
        let vector = std::mem::size_of::<Vec<u16>>();
        for input in [0, 1, 4096, 65536, MAX_BODY - 1, MAX_BODY] {
            let old = 2 * input + API_TEXT_VIEW + vector;
            let unknown = BridgePlan::new(input, true, MAX_BODY).unwrap();
            assert_eq!(unknown.cost(), Some(old));
            for output in [0, input, MAX_BODY] {
                let plan = BridgePlan::new(input, true, output).unwrap();
                assert!(plan.view_capacity >= 2 * input);
                assert!(plan.view_capacity >= 3 * output);
                assert!(plan.cost().unwrap() <= old);
                if plan.allows_utf8_input(input) {
                    assert!(plan.view_capacity >= 3 * input + 1);
                }
            }
        }
        assert!(
            !BridgePlan::new(MAX_BODY, true, MAX_BODY)
                .unwrap()
                .allows_utf8_input(MAX_BODY)
        );
        assert_eq!(BridgePlan::new(MAX_BODY + 1, true, 0), None);
        assert_eq!(BridgePlan::new(0, true, MAX_BODY + 1), None);
    }

    use super::*;
    #[test]
    fn ledger_identity_tracks_the_owner_not_equal_limits_or_charges() {
        let left = Budget::default();
        let right = Budget::default();
        let left_alias = left.clone();
        let bytes = BudgetedBytes::copy(&left, b"same").unwrap();
        let other = BudgetedBytes::copy(&right, b"same").unwrap();
        assert_eq!(left.used(), right.used());
        assert!(bytes.budget().same_ledger(&left_alias));
        assert!(!bytes.budget().same_ledger(other.budget()));
        let cost = left.used();
        let wire = bytes.into_bytes();
        let slice = wire.slice(1..2);
        drop(wire);
        assert_eq!(left.used(), cost);
        drop(slice);
        // The ledger alias itself owns no payload reservation.
        assert_eq!(left.used(), 0);
        drop(other);
        assert_eq!(right.used(), 0);
        drop(left_alias);
    }

    #[cfg(feature = "inbound-http")]
    #[test]
    fn initialized_output_scratch_never_allocates_and_keeps_capacity_charged() {
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, 4).unwrap();
        let cost = budget.used();
        output
            .write_initialized_output(4, |bytes| {
                assert_eq!(bytes, &[0, 0, 0, 0]);
                bytes.copy_from_slice(b"a\0b\0");
                Ok(3)
            })
            .unwrap();
        assert_eq!(output.as_ref(), b"a\0b");
        assert_eq!(output.remaining(), 1);
        assert_eq!(budget.used(), cost);
        let retained = output.into_bytes();
        let owner = retained.slice(1..);
        drop(retained);
        assert_eq!(&owner[..], b"\0b");
        assert_eq!(budget.used(), cost);
        drop(owner);
        assert_eq!(budget.used(), 0);
    }

    #[cfg(feature = "inbound-http")]
    #[test]
    fn initialized_output_scratch_rejects_growth_and_clears_failed_copy() {
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, 4).unwrap();
        let cost = budget.used();
        assert_eq!(
            output
                .write_initialized_output(5, |_| panic!("unadmitted scratch"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), cost);
        assert_eq!(
            output
                .write_initialized_output(4, |_| Err(io::ErrorKind::InvalidData.into()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(output.as_ref().is_empty());
        assert!(output.write_initialized_output(4, |_| Ok(5)).is_err());
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), cost);
        output.extend(b"kept").unwrap();
        assert!(output.write_initialized_output(0, |_| Ok(0)).is_err());
        assert_eq!(output.as_ref(), b"kept");
        drop(output);
        assert_eq!(budget.used(), 0);
    }

    #[cfg(feature = "inbound-http")]
    #[test]
    fn bridge_api_temporary_reservations_are_separate_from_output_allocations() {
        let budget = Budget::default();
        let output = BudgetedBytes::new(&budget, MAX_BODY).unwrap();
        let output_cost = budget.used();
        let view = output.reserve_temporary(API_TEXT_VIEW).unwrap();
        assert_eq!(budget.used(), output_cost + API_TEXT_VIEW);
        assert!(view.covers(&output, API_TEXT_VIEW));
        assert!(!view.covers(&output, API_TEXT_VIEW + 1));
        let other = BudgetedBytes::empty(&Budget::default());
        assert!(!view.covers(&other, API_TEXT_VIEW));
        drop(output);
        assert_eq!(budget.used(), API_TEXT_VIEW);
        drop(view);
        assert_eq!(budget.used(), 0);
    }

    #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
    #[test]
    fn merged_reservations_keep_the_same_ledger_and_one_final_refund() {
        let budget = Budget::default();
        let mut retained = budget.reserve(128).unwrap();
        assert!(retained.merge(budget.reserve(256).unwrap()).is_ok());
        assert_eq!(budget.used(), 384);
        let other = Budget::default();
        let rejected = retained.merge(other.reserve(64).unwrap()).err().unwrap();
        assert_eq!(budget.used(), 384);
        assert_eq!(other.used(), 64);
        drop(rejected);
        assert_eq!(other.used(), 0);
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn ownership_survives_bytes_clone_and_slice() {
        let budget = Budget::default();
        let output = BudgetedBytes::copy(&budget, b"original")
            .unwrap()
            .into_bytes();
        let retained = output.slice(2..5);
        drop(output);
        assert!(budget.used() >= 8);
        assert_eq!(&retained[..], b"igi");
        drop(retained);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn full_workspace_never_waits_and_drop_restores_admission() {
        let budget = Budget::default();
        let reservation = budget.reserve(WORKSPACE).unwrap();
        assert!(BudgetedBytes::new(&budget, 1).is_none());
        drop(reservation);
        assert!(BudgetedBytes::new(&budget, MAX_BODY).is_some());
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(all(test, unix, feature = "inbound-http"))]
#[path = "body_budget/mapped_output_tests.rs"]
mod mapped_output_tests;
