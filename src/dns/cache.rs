//! Single-owner hash index and safe slot-linked DNS retention order.

use std::{collections::HashMap, sync::Arc, time::Instant};

use super::{
    CacheValue, DnsError, MAX_OPAQUE_CACHE_BYTES, MAX_OPAQUE_CACHE_ENTRIES, QueryType, Result,
    WireQuestion,
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) enum Key {
    Address(String, QueryType),
    Opaque(WireQuestion, [u8; 32]),
}

#[derive(Debug)]
pub(super) enum Value {
    Address(CacheValue),
    Opaque {
        wire: Box<[u8]>,
        ttl_offsets: Box<[u16]>,
        accounted_bytes: usize,
    },
}

impl Value {
    fn opaque_bytes(&self) -> Option<usize> {
        match self {
            Self::Address(_) => None,
            Self::Opaque {
                accounted_bytes, ..
            } => Some(*accounted_bytes),
        }
    }
}

#[derive(Debug)]
struct Entry {
    key: Arc<Key>,
    value: Value,
    expires_at: Instant,
    previous: Option<usize>,
    next: Option<usize>,
    opaque_previous: Option<usize>,
    opaque_next: Option<usize>,
}

#[derive(Debug)]
enum Slot {
    Occupied(Entry),
    Vacant(Option<usize>),
}

/// Metadata retained alongside each opaque payload is part of its byte budget.
pub(super) const fn opaque_metadata_bytes() -> usize {
    std::mem::size_of::<Slot>()
        + std::mem::size_of::<Key>()
        + std::mem::size_of::<(Arc<Key>, usize)>()
        + 2 * std::mem::size_of::<usize>() // Arc reference counters
}

/// One role's total result budget, shared by address and opaque questions.
/// Slots and the hash table start empty and grow only after an actual insert.
/// Separate opaque links permit byte-budget eviction without scanning typed
/// entries or evicting an unrelated address result.
#[derive(Debug)]
pub(super) struct Store {
    index: HashMap<Arc<Key>, usize>,
    slots: Vec<Slot>,
    free: Option<usize>,
    least_recent: Option<usize>,
    most_recent: Option<usize>,
    opaque_least_recent: Option<usize>,
    opaque_most_recent: Option<usize>,
    max_entries: usize,
    opaque_entries: usize,
    opaque_bytes: usize,
}

impl Store {
    pub(super) fn new(max_entries: usize) -> Self {
        assert!(max_entries != 0, "DNS cache capacity must be non-zero");
        Self {
            index: HashMap::new(),
            slots: Vec::new(),
            free: None,
            least_recent: None,
            most_recent: None,
            opaque_least_recent: None,
            opaque_most_recent: None,
            max_entries,
            opaque_entries: 0,
            opaque_bytes: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.index.len()
    }

    pub(super) const fn opaque_len(&self) -> usize {
        self.opaque_entries
    }

    pub(super) const fn opaque_bytes(&self) -> usize {
        self.opaque_bytes
    }

    pub(super) fn clear(&mut self) {
        *self = Self::new(self.max_entries);
    }

    pub(super) fn get(&mut self, key: &Key, now: Instant) -> Option<(&Value, Instant)> {
        let slot = *self.index.get(key)?;
        if self.entry(slot).expires_at <= now {
            self.remove(slot);
            return None;
        }
        self.unlink(slot);
        self.append(slot);
        let entry = self.entry(slot);
        Some((&entry.value, entry.expires_at))
    }

    pub(super) fn insert(&mut self, key: Key, value: Value, expires_at: Instant) -> Result<()> {
        let replaced = self.index.get(&key).copied();
        if replaced.is_none() && self.len() < self.max_entries {
            self.index
                .try_reserve(1)
                .map_err(|_| DnsError::CacheAllocation)?;
            if self.free.is_none() {
                super::reserve_entry_slot(&mut self.slots, self.max_entries)?;
            }
        }
        if let Some(slot) = replaced {
            self.remove(slot);
        }
        if let Some(bytes) = value.opaque_bytes() {
            while self.opaque_entries >= MAX_OPAQUE_CACHE_ENTRIES
                || self.opaque_bytes.saturating_add(bytes) > MAX_OPAQUE_CACHE_BYTES
            {
                let Some(slot) = self.opaque_least_recent else {
                    return Err(DnsError::CacheAllocation);
                };
                self.remove(slot);
            }
        }
        if self.len() >= self.max_entries {
            self.remove(
                self.least_recent
                    .expect("full cache has a least recent entry"),
            );
        }
        let slot = if let Some(slot) = self.free {
            let Slot::Vacant(next) = self.slots[slot] else {
                unreachable!("free cache slot must be vacant");
            };
            self.free = next;
            slot
        } else {
            self.slots.push(Slot::Vacant(None));
            self.slots.len() - 1
        };
        let key = Arc::new(key);
        if let Some(bytes) = value.opaque_bytes() {
            self.opaque_entries += 1;
            self.opaque_bytes += bytes;
        }
        self.index.insert(key.clone(), slot);
        self.slots[slot] = Slot::Occupied(Entry {
            key,
            value,
            expires_at,
            previous: None,
            next: None,
            opaque_previous: None,
            opaque_next: None,
        });
        self.append(slot);
        debug_assert!(self.len() <= self.max_entries);
        debug_assert!(self.slots.len() <= self.max_entries);
        debug_assert!(self.opaque_entries <= MAX_OPAQUE_CACHE_ENTRIES);
        debug_assert!(self.opaque_bytes <= MAX_OPAQUE_CACHE_BYTES);
        Ok(())
    }

    fn entry(&self, slot: usize) -> &Entry {
        match &self.slots[slot] {
            Slot::Occupied(entry) => entry,
            Slot::Vacant(_) => unreachable!("linked cache slot must be occupied"),
        }
    }

    fn entry_mut(&mut self, slot: usize) -> &mut Entry {
        match &mut self.slots[slot] {
            Slot::Occupied(entry) => entry,
            Slot::Vacant(_) => unreachable!("linked cache slot must be occupied"),
        }
    }

    fn unlink(&mut self, slot: usize) {
        let entry = self.entry(slot);
        let (previous, next) = (entry.previous, entry.next);
        let opaque = entry.value.opaque_bytes().is_some();
        let (opaque_previous, opaque_next) = (entry.opaque_previous, entry.opaque_next);
        if let Some(previous) = previous {
            self.entry_mut(previous).next = next;
        } else {
            self.least_recent = next;
        }
        if let Some(next) = next {
            self.entry_mut(next).previous = previous;
        } else {
            self.most_recent = previous;
        }
        if opaque {
            if let Some(previous) = opaque_previous {
                self.entry_mut(previous).opaque_next = opaque_next;
            } else {
                self.opaque_least_recent = opaque_next;
            }
            if let Some(next) = opaque_next {
                self.entry_mut(next).opaque_previous = opaque_previous;
            } else {
                self.opaque_most_recent = opaque_previous;
            }
        }
    }

    fn append(&mut self, slot: usize) {
        let previous = self.most_recent;
        let opaque_previous = self.opaque_most_recent;
        let entry = self.entry_mut(slot);
        entry.previous = previous;
        entry.next = None;
        let opaque = entry.value.opaque_bytes().is_some();
        if let Some(previous) = previous {
            self.entry_mut(previous).next = Some(slot);
        } else {
            self.least_recent = Some(slot);
        }
        self.most_recent = Some(slot);
        if opaque {
            let entry = self.entry_mut(slot);
            entry.opaque_previous = opaque_previous;
            entry.opaque_next = None;
            if let Some(previous) = opaque_previous {
                self.entry_mut(previous).opaque_next = Some(slot);
            } else {
                self.opaque_least_recent = Some(slot);
            }
            self.opaque_most_recent = Some(slot);
        }
    }

    fn remove(&mut self, slot: usize) {
        self.unlink(slot);
        let Slot::Occupied(entry) =
            std::mem::replace(&mut self.slots[slot], Slot::Vacant(self.free))
        else {
            unreachable!("removed cache slot must be occupied");
        };
        self.free = Some(slot);
        self.index.remove(entry.key.as_ref());
        if let Some(bytes) = entry.value.opaque_bytes() {
            self.opaque_entries -= 1;
            self.opaque_bytes -= bytes;
        }
    }

    #[cfg(test)]
    pub(super) fn allocated_slots(&self) -> usize {
        self.slots.capacity()
    }
}
