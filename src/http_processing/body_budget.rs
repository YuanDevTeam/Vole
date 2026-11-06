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
pub(crate) const WORKSPACE: usize = 2 * 1024 * 1024;

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
    bytes: Vec<u8>,
    _reservation: Reservation,
}

impl BudgetedBytes {
    /// Same ledger for a private API view when no prepaid slot is available.
    #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
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
            bytes: Vec::new(),
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

    pub(crate) fn from_reserved(reservation: Reservation, capacity: usize) -> Option<Self> {
        if reservation.bytes != Self::allocation_cost(capacity)? {
            return None;
        }
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(capacity).ok()?;
        // Vec's allocation policy is allowed to return more than requested.
        // Never silently retain an unreserved capacity.
        if buffer.capacity() > capacity {
            return None;
        }
        Some(Self {
            bytes: buffer,
            _reservation: reservation,
        })
    }

    /// Admit a known result before copying it out of an engine. Body-less calls
    /// use an empty buffer until the backend knows that a result has a body.
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
        if !self.bytes.is_empty() {
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
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Let a C API fill initialized bytes inside an existing admitted allocation.
    /// The callback returns the retained length; scratch bytes remain charged
    /// through this owner's unchanged capacity and are never exposed as body.
    #[cfg(feature = "inbound-http")]
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    pub(crate) fn write_initialized_output(
        &mut self,
        length: usize,
        operation: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<()> {
        if !self.bytes.is_empty() || length > MAX_BODY || length > self.remaining() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP script output scratch is not available",
            ));
        }
        // The capacity check above prevents resize from allocating. Every byte
        // passed to the callback is initialized, including terminator scratch.
        self.bytes.resize(length, 0);
        match operation(&mut self.bytes) {
            Ok(retained) if retained <= length => {
                self.bytes.truncate(retained);
                Ok(())
            }
            Ok(_) => {
                self.bytes.clear();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP script output scratch length is invalid",
                ))
            }
            Err(error) => {
                self.bytes.clear();
                Err(error)
            }
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.capacity() - self.bytes.len()
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }

    pub(crate) fn write_text(
        &mut self,
        operation: impl FnOnce(&mut String) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut text = String::from_utf8(std::mem::take(&mut self.bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP body text is invalid"))?;
        let result = operation(&mut text);
        self.bytes = text.into_bytes();
        result
    }
}

impl AsRef<[u8]> for BudgetedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
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
