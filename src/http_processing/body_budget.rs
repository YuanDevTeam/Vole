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
        self.0
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.0.limit)
            })
            .ok()?;
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
    }
}

/// A fixed-capacity allocation. Its reservation follows every Bytes slice and
/// is released only when the last sender/driver has dropped the actual owner.
pub(crate) struct BudgetedBytes {
    bytes: Vec<u8>,
    _reservation: Reservation,
}

impl BudgetedBytes {
    pub(crate) fn new(budget: &Budget, capacity: usize) -> Option<Self> {
        let bytes = capacity.checked_add(std::mem::size_of::<Self>())?;
        let reservation = budget.reserve(bytes)?;
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
    use super::*;
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
