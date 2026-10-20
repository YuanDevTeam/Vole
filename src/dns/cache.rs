//! Single-owner hash index and safe slot-linked DNS retention order.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    CacheLookup, CacheValue, DnsError, MAX_OPAQUE_CACHE_BYTES, MAX_OPAQUE_CACHE_ENTRIES, QueryType,
    Result, WireQuestion,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum List {
    Recent,
    Frequent,
    RecentGhost,
    FrequentGhost,
    Lru,
}

impl List {
    const fn is_ghost(self) -> bool {
        matches!(self, Self::RecentGhost | Self::FrequentGhost)
    }
}

#[derive(Debug, Default)]
struct Chain {
    least: Option<usize>,
    most: Option<usize>,
    len: usize,
}

#[derive(Debug)]
struct Entry {
    key: Arc<Key>,
    value: Option<Value>,
    expires_at: Instant,
    stale_eligible: bool,
    refresh_after: Instant,
    list: List,
    previous: Option<usize>,
    next: Option<usize>,
    opaque_previous: Option<usize>,
    opaque_next: Option<usize>,
}

impl Entry {
    fn opaque_bytes(&self) -> Option<usize> {
        match self.value.as_ref() {
            Some(value) => value.opaque_bytes(),
            None => self.key.opaque_metadata_bytes(),
        }
    }

    fn opaque_chain(&self) -> Option<usize> {
        self.opaque_bytes()
            .map(|_| usize::from(self.value.is_none()))
    }
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

impl Key {
    fn opaque_metadata_bytes(&self) -> Option<usize> {
        match self {
            Self::Address(..) => None,
            Self::Opaque(question, digest) => {
                Some(question.name.len() + 4 + digest.len() + opaque_metadata_bytes())
            }
        }
    }
}

/// Maximum additional age after a positive result's fresh expiry.
pub(super) const STALE_RETENTION: Duration = Duration::from_secs(3_600);

/// One role's shared result store. Hash/slot storage starts empty. LRU retains
/// at most c slots; ARC retains at most c payloads and c payload-free ghosts.
/// Active and ghost opaque chains allow byte-budget eviction without scanning
/// address results. Ghost key metadata remains charged to the opaque budget.
#[derive(Debug)]
pub(super) struct Store {
    index: HashMap<Arc<Key>, usize>,
    slots: Vec<Slot>,
    free: Option<usize>,
    lists: [Chain; 5],
    opaque: [Chain; 2],
    algorithm: crate::config::DnsCacheAlgorithm,
    recent_target: usize,
    max_entries: usize,
    resident_entries: usize,
    opaque_entries: usize,
    opaque_bytes: usize,
}

impl Store {
    pub(super) fn new(max_entries: usize) -> Self {
        Self::with_algorithm(max_entries, crate::config::DnsCacheAlgorithm::Lru)
    }

    pub(super) fn with_algorithm(
        max_entries: usize,
        algorithm: crate::config::DnsCacheAlgorithm,
    ) -> Self {
        assert!(max_entries != 0, "DNS cache capacity must be non-zero");
        Self {
            index: HashMap::new(),
            slots: Vec::new(),
            free: None,
            lists: std::array::from_fn(|_| Chain::default()),
            opaque: std::array::from_fn(|_| Chain::default()),
            algorithm,
            recent_target: 0,
            max_entries,
            resident_entries: 0,
            opaque_entries: 0,
            opaque_bytes: 0,
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.resident_entries
    }

    pub(super) const fn opaque_len(&self) -> usize {
        self.opaque_entries
    }
    pub(super) const fn opaque_bytes(&self) -> usize {
        self.opaque_bytes
    }

    fn metadata_limit(&self) -> usize {
        match self.algorithm {
            crate::config::DnsCacheAlgorithm::Lru => self.max_entries,
            crate::config::DnsCacheAlgorithm::Arc => self.max_entries.saturating_mul(2),
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self::with_algorithm(self.max_entries, self.algorithm);
    }

    #[cfg(test)]
    pub(super) fn get(&mut self, key: &Key, now: Instant) -> Option<(&Value, Instant)> {
        self.lookup(key, now, false).into_fresh()
    }

    /// Stale payloads remain residents in the existing count and byte budgets.
    /// A lookup never extends either the fresh expiry or the fixed stale age.
    pub(super) fn lookup(
        &mut self,
        key: &Key,
        now: Instant,
        allow_stale: bool,
    ) -> CacheLookup<(&Value, Instant)> {
        let Some(&slot) = self.index.get(key) else {
            return CacheLookup::Miss;
        };
        let entry = self.entry(slot);
        let stale = entry.expires_at <= now;
        if stale
            && (!allow_stale
                || !entry.stale_eligible
                || entry.value.is_none()
                || now.saturating_duration_since(entry.expires_at) >= STALE_RETENTION)
        {
            self.remove(slot);
            return CacheLookup::Miss;
        }
        if entry.value.is_none() {
            return CacheLookup::Miss;
        }
        // Repeated stale access may retain a resident, but does not count as
        // fresh frequency evidence or resurrect an ARC ghost payload.
        let list = if stale {
            entry.list
        } else {
            match self.algorithm {
                crate::config::DnsCacheAlgorithm::Lru => List::Lru,
                crate::config::DnsCacheAlgorithm::Arc => List::Frequent,
            }
        };
        self.unlink(slot);
        self.append(slot, list);
        let entry = self.entry(slot);
        let hit = (
            entry.value.as_ref().expect("resident entry has a payload"),
            entry.expires_at,
        );
        if stale {
            CacheLookup::Stale(hit)
        } else {
            CacheLookup::Fresh(hit)
        }
    }

    pub(super) fn reserve_refresh(&mut self, key: &Key, now: Instant, backoff: Duration) -> bool {
        let Some(&slot) = self.index.get(key) else {
            return false;
        };
        let entry = self.entry_mut(slot);
        if entry.value.is_none()
            || !entry.stale_eligible
            || entry.expires_at > now
            || entry.refresh_after > now
        {
            return false;
        }
        entry.refresh_after = now.checked_add(backoff).unwrap_or(now);
        true
    }

    pub(super) fn finish_refresh(&mut self, key: &Key, now: Instant, backoff: Duration) {
        if let Some(&slot) = self.index.get(key) {
            let entry = self.entry_mut(slot);
            if entry.expires_at <= now {
                entry.refresh_after = now.checked_add(backoff).unwrap_or(now);
            }
        }
    }

    pub(super) fn insert(
        &mut self,
        key: Key,
        value: Value,
        expires_at: Instant,
        now: Instant,
        stale_eligible: bool,
    ) -> Result<()> {
        let mut replaced = self.index.get(&key).copied();
        if let Some(slot) = replaced
            && self.entry(slot).expires_at <= now
        {
            self.remove(slot);
            replaced = None;
        }
        let previous_list = replaced.map(|slot| self.entry(slot).list);
        // Make allocation failure leave existing usable payloads untouched.
        let metadata_limit = self.metadata_limit();
        if replaced.is_none() && self.index.len() < metadata_limit {
            self.index
                .try_reserve(1)
                .map_err(|_| DnsError::CacheAllocation)?;
            if self.free.is_none() {
                super::reserve_entry_slot(&mut self.slots, metadata_limit)?;
            }
        }
        if previous_list == Some(List::RecentGhost) {
            let step =
                (self.list_len(List::FrequentGhost) / self.list_len(List::RecentGhost)).max(1);
            self.recent_target = self
                .recent_target
                .saturating_add(step)
                .min(self.max_entries);
        } else if previous_list == Some(List::FrequentGhost) {
            let step =
                (self.list_len(List::RecentGhost) / self.list_len(List::FrequentGhost)).max(1);
            self.recent_target = self.recent_target.saturating_sub(step);
        }
        if let Some(slot) = replaced {
            self.remove(slot);
        }
        let destination = match self.algorithm {
            crate::config::DnsCacheAlgorithm::Lru => {
                if self.len() >= self.max_entries {
                    self.remove_lru(List::Lru);
                }
                List::Lru
            }
            crate::config::DnsCacheAlgorithm::Arc => match previous_list {
                Some(List::Recent | List::Frequent) => List::Frequent,
                Some(list) if list.is_ghost() => {
                    if self.len() >= self.max_entries {
                        self.replace(list == List::FrequentGhost);
                    }
                    List::Frequent
                }
                _ => {
                    self.prepare_recent();
                    List::Recent
                }
            },
        };
        if let Some(bytes) = value.opaque_bytes() {
            while self.opaque_entries >= MAX_OPAQUE_CACHE_ENTRIES
                || self.opaque_bytes.saturating_add(bytes) > MAX_OPAQUE_CACHE_BYTES
            {
                // Discard metadata first; a byte-budget eviction is not an ARC
                // capacity miss and does not change the adaptive target.
                let candidate = self.opaque[1]
                    .least
                    .or(self.opaque[0].least)
                    .ok_or(DnsError::CacheAllocation)?;
                self.remove(candidate);
            }
        }
        self.trim_ghosts();
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
        self.resident_entries += 1;
        self.index.insert(key.clone(), slot);
        self.slots[slot] = Slot::Occupied(Entry {
            key,
            value: Some(value),
            expires_at,
            stale_eligible,
            refresh_after: expires_at,
            list: destination,
            previous: None,
            next: None,
            opaque_previous: None,
            opaque_next: None,
        });
        self.append(slot, destination);
        debug_assert!(self.len() <= self.max_entries);
        debug_assert!(self.index.len() <= metadata_limit);
        debug_assert!(self.slots.len() <= metadata_limit);
        debug_assert!(self.opaque_entries <= MAX_OPAQUE_CACHE_ENTRIES);
        debug_assert!(self.opaque_bytes <= MAX_OPAQUE_CACHE_BYTES);
        Ok(())
    }

    fn list_len(&self, list: List) -> usize {
        self.lists[list as usize].len
    }

    fn prepare_recent(&mut self) {
        let recent_and_ghost = self.list_len(List::Recent) + self.list_len(List::RecentGhost);
        if recent_and_ghost == self.max_entries {
            if self.list_len(List::Recent) < self.max_entries {
                self.remove_lru(List::RecentGhost);
                if self.len() >= self.max_entries {
                    self.replace(false);
                }
            } else {
                self.remove_lru(List::Recent);
            }
        } else if self.index.len() >= self.max_entries {
            if self.index.len() >= self.metadata_limit() && !self.remove_lru(List::FrequentGhost) {
                self.remove_lru(List::RecentGhost);
            }
            if self.len() >= self.max_entries {
                self.replace(false);
            }
        }
    }

    fn replace(&mut self, incoming_frequent_ghost: bool) {
        let recent = self.list_len(List::Recent);
        let from_recent = recent != 0
            && (recent > self.recent_target
                || (incoming_frequent_ghost && recent == self.recent_target));
        let (from, to) = if from_recent {
            (List::Recent, List::RecentGhost)
        } else {
            (List::Frequent, List::FrequentGhost)
        };
        let slot = self.lists[from as usize]
            .least
            .expect("full ARC has a replacement entry");
        self.unlink(slot);
        let value = self
            .entry_mut(slot)
            .value
            .take()
            .expect("ARC resident has a payload");
        self.resident_entries -= 1;
        if let Some(bytes) = value.opaque_bytes() {
            self.opaque_entries -= 1;
            self.opaque_bytes -= bytes
                - self
                    .entry(slot)
                    .key
                    .opaque_metadata_bytes()
                    .expect("opaque key metadata");
        }
        drop(value);
        self.append(slot, to);
    }

    fn trim_ghosts(&mut self) {
        while self.list_len(List::RecentGhost) + self.list_len(List::FrequentGhost)
            > self.max_entries
            || self.index.len() >= self.metadata_limit()
        {
            if !self.remove_lru(List::FrequentGhost) && !self.remove_lru(List::RecentGhost) {
                break;
            }
        }
    }

    fn remove_lru(&mut self, list: List) -> bool {
        if let Some(slot) = self.lists[list as usize].least {
            self.remove(slot);
            true
        } else {
            false
        }
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
        let list = entry.list as usize;
        let (previous, next) = (entry.previous, entry.next);
        let opaque_chain = entry.opaque_chain();
        let (opaque_previous, opaque_next) = (entry.opaque_previous, entry.opaque_next);
        if let Some(previous) = previous {
            self.entry_mut(previous).next = next;
        } else {
            self.lists[list].least = next;
        }
        if let Some(next) = next {
            self.entry_mut(next).previous = previous;
        } else {
            self.lists[list].most = previous;
        }
        self.lists[list].len -= 1;
        if let Some(chain) = opaque_chain {
            if let Some(previous) = opaque_previous {
                self.entry_mut(previous).opaque_next = opaque_next;
            } else {
                self.opaque[chain].least = opaque_next;
            }
            if let Some(next) = opaque_next {
                self.entry_mut(next).opaque_previous = opaque_previous;
            } else {
                self.opaque[chain].most = opaque_previous;
            }
            self.opaque[chain].len -= 1;
        }
    }

    fn append(&mut self, slot: usize, list: List) {
        let previous = self.lists[list as usize].most;
        let opaque_chain = self.entry(slot).opaque_chain();
        let entry = self.entry_mut(slot);
        entry.list = list;
        entry.previous = previous;
        entry.next = None;
        if let Some(previous) = previous {
            self.entry_mut(previous).next = Some(slot);
        } else {
            self.lists[list as usize].least = Some(slot);
        }
        self.lists[list as usize].most = Some(slot);
        self.lists[list as usize].len += 1;
        if let Some(chain) = opaque_chain {
            let previous = self.opaque[chain].most;
            let entry = self.entry_mut(slot);
            entry.opaque_previous = previous;
            entry.opaque_next = None;
            if let Some(previous) = previous {
                self.entry_mut(previous).opaque_next = Some(slot);
            } else {
                self.opaque[chain].least = Some(slot);
            }
            self.opaque[chain].most = Some(slot);
            self.opaque[chain].len += 1;
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
        if entry.value.is_some() {
            self.resident_entries -= 1;
        }
        if let Some(bytes) = entry.opaque_bytes() {
            if entry.value.is_some() {
                self.opaque_entries -= 1;
            }
            self.opaque_bytes -= bytes;
        }
    }

    #[cfg(test)]
    pub(super) fn allocated_slots(&self) -> usize {
        self.slots.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsCacheAlgorithm;
    use std::{net::Ipv4Addr, time::Duration};

    fn address(name: &str) -> Key {
        Key::Address(name.into(), QueryType::A)
    }

    fn put(store: &mut Store, name: &str, now: Instant) {
        store
            .insert(
                address(name),
                Value::Address(CacheValue::Positive(vec![Ipv4Addr::LOCALHOST.into()])),
                now + Duration::from_secs(60),
                now,
                true,
            )
            .unwrap();
    }

    fn opaque_key(name: &str) -> Key {
        Key::Opaque(
            WireQuestion {
                name: name.into(),
                query_type: 16,
                query_class: 1,
            },
            [0; 32],
        )
    }

    fn put_opaque(store: &mut Store, name: &str, now: Instant, ttl: u64) {
        let key = opaque_key(name);
        let accounted_bytes = key.opaque_metadata_bytes().unwrap() + 4096 + 2;
        store
            .insert(
                key,
                Value::Opaque {
                    wire: vec![0_u8; 4096].into_boxed_slice(),
                    ttl_offsets: vec![8].into_boxed_slice(),
                    accounted_bytes,
                },
                now + Duration::from_secs(ttl),
                now,
                true,
            )
            .unwrap();
    }

    #[test]
    fn stale_positive_age_is_fixed_and_does_not_turn_ghosts_into_payloads() {
        let now = Instant::now();
        for algorithm in [DnsCacheAlgorithm::Lru, DnsCacheAlgorithm::Arc] {
            let mut store = Store::with_algorithm(2, algorithm);
            put(&mut store, "a", now);
            assert!(matches!(
                store.lookup(&address("a"), now, true),
                CacheLookup::Fresh(_)
            ));
            let expires = now + Duration::from_secs(60);
            assert!(matches!(
                store.lookup(&address("a"), expires, true),
                CacheLookup::Stale(_)
            ));
            assert!(matches!(
                store.lookup(
                    &address("a"),
                    expires + STALE_RETENTION - Duration::from_secs(1),
                    true
                ),
                CacheLookup::Stale(_)
            ));
            assert!(matches!(
                store.lookup(&address("a"), expires + STALE_RETENTION, true),
                CacheLookup::Miss
            ));
            assert_eq!(store.len(), 0);

            put(&mut store, "a", now);
            store.get(&address("a"), now).unwrap();
            put_opaque(&mut store, "b", now, 60);
            put(&mut store, "c", now);
            if algorithm == DnsCacheAlgorithm::Arc {
                let ghost = store.entry(*store.index.get(&opaque_key("b")).unwrap());
                assert!(ghost.value.is_none());
                assert!(matches!(
                    store.lookup(&opaque_key("b"), now, true),
                    CacheLookup::Miss
                ));
                assert_eq!(store.opaque_len(), 0);
                assert_eq!(store.recent_target, 0);
            }
        }
    }

    #[test]
    fn stale_mixed_results_use_the_same_resident_and_opaque_budgets() {
        let now = Instant::now();
        let stale = now + Duration::from_secs(61);
        for algorithm in [DnsCacheAlgorithm::Lru, DnsCacheAlgorithm::Arc] {
            let mut store = Store::with_algorithm(64, algorithm);
            for index in 0..64 {
                put_opaque(&mut store, &format!("wire{index}"), now, 60);
            }
            let bytes = store.opaque_bytes();
            let mut stale_hits = 0;
            for index in 0..64 {
                stale_hits += usize::from(matches!(
                    store.lookup(&opaque_key(&format!("wire{index}")), stale, true),
                    CacheLookup::Stale(_)
                ));
            }
            assert!(stale_hits > 0);
            assert_eq!(store.opaque_bytes(), bytes);
            for index in 0..200 {
                put_opaque(&mut store, &format!("new{index}"), stale, 60);
                if index % 4 == 0 {
                    put(&mut store, &format!("typed{index}"), stale);
                }
                assert!(store.len() <= 64);
                assert!(store.opaque_len() <= MAX_OPAQUE_CACHE_ENTRIES);
                assert!(store.opaque_bytes() <= MAX_OPAQUE_CACHE_BYTES);
                assert!(store.index.len() <= store.metadata_limit());
                assert!(store.slots.len() <= store.metadata_limit());
            }
            store.clear();
            assert_eq!(store.len(), 0);
            assert_eq!(store.opaque_bytes(), 0);
            assert_eq!(store.allocated_slots(), 0);
        }
    }

    #[test]
    fn arc_preserves_a_frequent_result_that_lru_evicts_during_a_scan() {
        let now = Instant::now();
        for (algorithm, retained) in [
            (DnsCacheAlgorithm::Lru, false),
            (DnsCacheAlgorithm::Arc, true),
        ] {
            let mut store = Store::with_algorithm(2, algorithm);
            put(&mut store, "a", now);
            assert!(store.get(&address("a"), now).is_some());
            put(&mut store, "b", now);
            put(&mut store, "c", now);
            assert_eq!(store.get(&address("a"), now).is_some(), retained);
            assert_eq!(store.len(), 2);
        }
    }

    #[test]
    fn arc_ghost_hits_adapt_in_both_directions_and_release_wire_payloads() {
        let now = Instant::now();
        let mut store = Store::with_algorithm(2, DnsCacheAlgorithm::Arc);
        put(&mut store, "a", now);
        store.get(&address("a"), now).unwrap();
        put_opaque(&mut store, "b", now, 60);
        put(&mut store, "c", now);
        let ghost = store.entry(*store.index.get(&opaque_key("b")).unwrap());
        assert_eq!(ghost.list, List::RecentGhost);
        assert!(ghost.value.is_none());
        assert_eq!(store.opaque_entries, 0);
        assert_eq!(
            store.opaque_bytes,
            opaque_key("b").opaque_metadata_bytes().unwrap()
        );
        put_opaque(&mut store, "b", now, 60);
        assert_eq!(store.recent_target, 1);
        let ghost = store.entry(*store.index.get(&address("a")).unwrap());
        assert_eq!(ghost.list, List::FrequentGhost);
        assert!(ghost.value.is_none());
        put(&mut store, "a", now);
        assert_eq!(store.recent_target, 0);
        assert!(store.get(&address("a"), now).is_some());
        assert!(store.get(&opaque_key("b"), now).is_some());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn arc_expired_residents_and_ghosts_are_removed_without_learning_a_hit() {
        let now = Instant::now();
        let mut store = Store::with_algorithm(2, DnsCacheAlgorithm::Arc);
        put(&mut store, "a", now);
        store.get(&address("a"), now).unwrap();
        put_opaque(&mut store, "b", now, 30);
        store
            .insert(
                address("c"),
                Value::Address(CacheValue::Negative { rcode: 3 }),
                now + Duration::from_secs(30),
                now,
                false,
            )
            .unwrap();
        let expired = now + Duration::from_secs(31);
        assert!(store.get(&opaque_key("b"), expired).is_none());
        assert_eq!(store.opaque_bytes, 0);
        assert!(store.get(&address("c"), expired).is_none());
        assert_eq!(store.len(), 1);
        put_opaque(&mut store, "b", expired, 60);
        assert_eq!(store.recent_target, 0);
        assert_eq!(
            store
                .entry(*store.index.get(&opaque_key("b")).unwrap())
                .list,
            List::Recent
        );
    }

    #[test]
    fn arc_mixed_payloads_keep_resident_ghost_and_opaque_budgets_bounded() {
        let now = Instant::now();
        let mut store = Store::with_algorithm(64, DnsCacheAlgorithm::Arc);
        assert_eq!(store.allocated_slots(), 0);
        for index in 0..600 {
            if index % 6 == 0 {
                put(&mut store, &format!("typed{index}"), now);
            } else {
                put_opaque(&mut store, &format!("wire{index}"), now, 60);
            }
            if index % 3 == 0 {
                store.get(&opaque_key(&format!("wire{}", index - index % 6 + 1)), now);
            }
            assert!(store.len() <= 64);
            assert!(store.index.len() <= 128);
            assert!(store.slots.len() <= 128);
            assert!(store.list_len(List::RecentGhost) + store.list_len(List::FrequentGhost) <= 64);
            assert!(store.list_len(List::Recent) + store.list_len(List::RecentGhost) <= 64);
            assert!(store.recent_target <= 64);
            assert!(store.opaque_entries <= MAX_OPAQUE_CACHE_ENTRIES);
            assert!(store.opaque_bytes <= MAX_OPAQUE_CACHE_BYTES);
            let mut resident = 0;
            let mut opaque = 0;
            let mut bytes = 0;
            for slot in store.index.values() {
                let entry = store.entry(*slot);
                assert_eq!(entry.value.is_none(), entry.list.is_ghost());
                resident += usize::from(entry.value.is_some());
                if let Some(retained) = entry.opaque_bytes() {
                    opaque += usize::from(entry.value.is_some());
                    bytes += retained;
                }
            }
            assert_eq!(store.len(), resident);
            assert_eq!(store.opaque_entries, opaque);
            assert_eq!(store.opaque_bytes, bytes);
        }
        store.clear();
        assert_eq!(store.len(), 0);
        assert_eq!(store.opaque_bytes, 0);
        assert_eq!(store.allocated_slots(), 0);
        assert_eq!(store.index.capacity(), 0);
    }
}
