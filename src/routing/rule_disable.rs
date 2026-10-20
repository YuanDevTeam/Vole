//! Generation-local rule switches, published as one immutable bounded snapshot.
use arc_swap::ArcSwapOption;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(crate) struct RuleDisable {
    count: usize,
    current: ArcSwapOption<Bits>,
    updates: Mutex<()>,
}

#[derive(Debug, PartialEq, Eq)]
struct Bits(Box<[u64]>);
impl Bits {
    fn contains(&self, index: usize) -> bool {
        self.0
            .get(index / 64)
            .is_some_and(|word| word & (1 << (index % 64)) != 0)
    }
}

/// A routing decision keeps the same switches across DNS/process continuations.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Snapshot(Option<Arc<Bits>>);
impl Snapshot {
    pub(super) fn contains(&self, index: usize) -> bool {
        self.0.as_ref().is_some_and(|bits| bits.contains(index))
    }
}

impl RuleDisable {
    pub(super) fn new(count: usize) -> Self {
        Self {
            count,
            current: ArcSwapOption::empty(),
            updates: Mutex::new(()),
        }
    }
    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot(self.current.load_full())
    }
    pub(crate) fn apply(&self, changes: &[(usize, bool)]) -> Result<(), ()> {
        if changes.iter().any(|(index, _)| *index >= self.count) {
            return Err(());
        }
        if changes.is_empty() {
            return Ok(());
        }
        // Publication takes its generation lock before entering here. This
        // additional lock also prevents lost concurrent updates for direct users.
        let _update = self.updates.lock().unwrap();
        let previous = self.current.load_full();
        if changes.iter().all(|(index, disabled)| {
            previous.as_ref().is_some_and(|bits| bits.contains(*index)) == *disabled
        }) {
            return Ok(());
        }
        let mut words = previous.as_ref().map_or_else(
            || vec![0_u64; self.count.div_ceil(64)],
            |bits| bits.0.to_vec(),
        );
        for (index, disabled) in changes {
            let mask = 1 << (index % 64);
            if *disabled {
                words[index / 64] |= mask;
            } else {
                words[index / 64] &= !mask;
            }
        }
        self.current.store(
            words
                .iter()
                .any(|word| *word != 0)
                .then(|| Arc::new(Bits(words.into_boxed_slice()))),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_validate_the_whole_patch_and_preserve_old_snapshots() {
        let state = RuleDisable::new(crate::config::MAX_RULES);
        assert!(state.current.load().is_none());
        state.apply(&[(0, false)]).unwrap();
        assert!(state.current.load().is_none());
        state
            .apply(&[(0, true), (crate::config::MAX_RULES - 1, true)])
            .unwrap();
        let old = state.snapshot();
        assert_eq!(old.0.as_ref().unwrap().0.len() * size_of::<u64>(), 8192);
        assert!(
            state
                .apply(&[(0, false), (crate::config::MAX_RULES, true)])
                .is_err()
        );
        assert!(state.snapshot().contains(0));
        state
            .apply(&[(0, false), (crate::config::MAX_RULES - 1, false)])
            .unwrap();
        assert!(state.current.load().is_none());
        assert!(old.contains(0));
        assert!(old.contains(crate::config::MAX_RULES - 1));
    }

    #[test]
    fn concurrent_patch_writers_do_not_lose_each_others_changes() {
        let state = Arc::new(RuleDisable::new(64));
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let state = &state;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    for index in (worker..64).step_by(8) {
                        state.apply(&[(index, true)]).unwrap();
                    }
                });
            }
        });
        let snapshot = state.snapshot();
        assert!((0..64).all(|index| snapshot.contains(index)));
    }
}
