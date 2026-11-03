//! Per-group selection; transports retain the selected leaf, not this cursor.
use crate::{
    config::{BalanceHashKey, BalanceStrategy},
    session::Destination,
};
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    net::SocketAddr,
    sync::OnceLock,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Debug)]
pub(super) struct Balance {
    strategy: BalanceStrategy,
    hash_key: BalanceHashKey,
    healthy: Vec<bool>,
    cursor: usize,
    sticky: HashMap<u64, Entry>,
    clock: u64,
}
#[derive(Debug)]
struct Entry {
    index: usize,
    expires: Instant,
    used: u64,
}

impl Balance {
    pub fn new(strategy: BalanceStrategy, members: usize) -> Self {
        Self {
            strategy,
            hash_key: BalanceHashKey::Default,
            healthy: vec![true; members],
            cursor: 0,
            sticky: HashMap::new(),
            clock: 0,
        }
    }
    pub fn with_hash_key(mut self, hash_key: BalanceHashKey) -> Self {
        self.hash_key = hash_key;
        self
    }
    pub fn health(&mut self, samples: &[Option<u64>]) {
        if samples.len() == self.healthy.len() {
            for (alive, sample) in self.healthy.iter_mut().zip(samples) {
                *alive = sample.is_some();
            }
        }
    }
    pub fn choose(
        &mut self,
        source: Option<SocketAddr>,
        destination: Option<&Destination>,
        user: Option<&str>,
    ) -> usize {
        self.inspect(source, destination, user, true)
    }
    pub fn inspect(
        &mut self,
        source: Option<SocketAddr>,
        destination: Option<&Destination>,
        user: Option<&str>,
        commit: bool,
    ) -> usize {
        let count = self.healthy.len();
        if count == 0 {
            return 0;
        }
        if self.strategy == BalanceStrategy::RoundRobin {
            let selected = (0..count)
                .map(|offset| (self.cursor + offset) % count)
                .find(|&i| self.healthy[i]);
            if let Some(index) = selected {
                if commit {
                    self.cursor = (index + 1) % count;
                }
                return index;
            }
            return 0;
        }
        let user = (self.hash_key == BalanceHashKey::InUser)
            .then_some(user)
            .flatten()
            .filter(|user| !user.is_empty());
        let fallback = user.is_none().then(|| {
            let mut key = destination_key(destination);
            if self.strategy == BalanceStrategy::StickySessions {
                key.insert_str(
                    0,
                    &source.map_or_else(|| "invalid IP".into(), |s| s.ip().to_string()),
                );
            }
            key
        });
        static HASH: OnceLock<RandomState> = OnceLock::new();
        let key = HASH
            .get_or_init(RandomState::new)
            .hash_one(user.unwrap_or_else(|| fallback.as_deref().unwrap()));
        if self.strategy == BalanceStrategy::ConsistentHashing {
            return (0..5)
                .map(|offset| jump(key.wrapping_add(offset), count))
                .find(|&i| self.healthy[i])
                .or_else(|| self.healthy.iter().position(|&v| v))
                .unwrap_or(0);
        }
        self.clock = self.clock.wrapping_add(1);
        let now = Instant::now();
        if let Some(entry) = self.sticky.get_mut(&key)
            && entry.expires > now
            && entry.index < count
            && self.healthy[entry.index]
        {
            entry.used = self.clock;
            return entry.index;
        }
        let index = healthy_candidate(
            &self.healthy,
            (0..4).map(|_| jump(key.wrapping_add(rand::random::<u64>()), count)),
        );
        if self.sticky.len() >= 1000
            && !self.sticky.contains_key(&key)
            && let Some(oldest) = self
                .sticky
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(&k, _)| k)
        {
            self.sticky.remove(&oldest);
        }
        self.sticky.insert(
            key,
            Entry {
                index,
                expires: now + Duration::from_secs(600),
                used: self.clock,
            },
        );
        index
    }
    pub fn commit(&mut self, index: usize) {
        if self.strategy == BalanceStrategy::RoundRobin && !self.healthy.is_empty() {
            self.cursor = (index + 1) % self.healthy.len();
        }
    }
}
fn healthy_candidate(healthy: &[bool], mut candidates: impl Iterator<Item = usize>) -> usize {
    candidates
        .find(|&i| healthy[i])
        .or_else(|| healthy.iter().position(|&alive| alive))
        .unwrap_or(0)
}
fn destination_key(destination: Option<&Destination>) -> String {
    match destination {
        Some(Destination::Ip(address)) => address.ip().to_string(),
        Some(Destination::Domain { host, .. }) => host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| psl::domain_str(host).unwrap_or_default().to_owned()),
        None => String::new(),
    }
}
// Jump consistent hash (Lamping and Veach); only the bucket count affects remapping.
fn jump(mut key: u64, count: usize) -> usize {
    let mut bucket = 0;
    let mut next = 0;
    while next < count {
        bucket = next;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        next = ((bucket + 1) as f64 * ((1_u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as usize;
    }
    bucket
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sticky_sampling_keeps_healthy_hits_and_falls_back_after_four_misses() {
        let mut attempts = 0;
        assert_eq!(
            healthy_candidate(
                &[false, false, true],
                [0, 1, 0, 1].into_iter().inspect(|_| attempts += 1),
            ),
            2
        );
        assert_eq!(attempts, 4);
        assert_eq!(
            healthy_candidate(&[false, true, true], [2, 1, 0, 0].into_iter()),
            2
        );
        assert_eq!(
            healthy_candidate(&[false, true, true], [0, 0, 0, 0].into_iter()),
            1
        );
        assert_eq!(
            healthy_candidate(&[false, false, false], [2, 1, 0, 2].into_iter()),
            0
        );
    }

    #[test]
    fn sticky_cache_replaces_unhealthy_and_out_of_range_members() {
        let source = Some("192.0.2.1:1234".parse().unwrap());
        let destination = Destination::domain("example.com", 443).unwrap();
        let mut sticky = Balance::new(BalanceStrategy::StickySessions, 3);
        sticky.health(&[Some(10), None, None]);
        assert_eq!(sticky.choose(source, Some(&destination), None), 0);

        sticky.health(&[None, None, Some(20)]);
        assert_eq!(sticky.choose(source, Some(&destination), None), 2);
        assert_eq!(sticky.sticky.len(), 1);
        assert_eq!(sticky.sticky.values().next().unwrap().index, 2);

        sticky.health(&[Some(10), Some(15), Some(20)]);
        assert_eq!(sticky.choose(source, Some(&destination), None), 2);

        // A stale cache index must never index the current member list.
        sticky.sticky.values_mut().next().unwrap().index = 3;
        sticky.health(&[None, Some(15), None]);
        assert_eq!(sticky.choose(source, Some(&destination), None), 1);
        assert_eq!(sticky.sticky.len(), 1);
        assert_eq!(sticky.sticky.values().next().unwrap().index, 1);
    }

    #[test]
    fn sticky_member_boundaries_keep_empty_and_all_unhealthy_fallbacks() {
        let mut empty = Balance::new(BalanceStrategy::StickySessions, 0);
        assert_eq!(empty.choose(None, None, None), 0);
        assert!(empty.sticky.is_empty());

        let mut single = Balance::new(BalanceStrategy::StickySessions, 1);
        assert_eq!(single.choose(None, None, None), 0);
        single.health(&[None]);
        assert_eq!(single.choose(None, None, None), 0);
        assert_eq!(single.sticky.len(), 1);

        let mut unhealthy = Balance::new(BalanceStrategy::StickySessions, 3);
        unhealthy.health(&[None, None, None]);
        assert_eq!(unhealthy.choose(None, None, None), 0);
        assert_eq!(unhealthy.sticky.values().next().unwrap().index, 0);
    }

    #[test]
    fn ingress_hash_uses_only_authenticated_user_and_keeps_address_fallback() {
        let a = Destination::domain("first.example.com", 443).unwrap();
        let b = Destination::domain("other.example.org", 80).unwrap();
        let first = Some("192.0.2.1:1234".parse().unwrap());
        let second = Some("203.0.113.2:4321".parse().unwrap());
        for strategy in [
            BalanceStrategy::ConsistentHashing,
            BalanceStrategy::StickySessions,
        ] {
            let mut balance = Balance::new(strategy, 7).with_hash_key(BalanceHashKey::InUser);
            let selected = balance.choose(first, Some(&a), Some("Alice"));
            assert_eq!(balance.choose(second, Some(&b), Some("Alice")), selected);
            assert_eq!(balance.choose(None, None, Some("Alice")), selected);
            if strategy == BalanceStrategy::StickySessions {
                assert_eq!(balance.sticky.len(), 1);
                balance.choose(first, Some(&a), None);
                assert_eq!(balance.sticky.len(), 2);
                // An empty identity falls back to exactly the same address key.
                balance.choose(first, Some(&a), Some(""));
                assert_eq!(balance.sticky.len(), 2);
            } else {
                let mut fallback = Balance::new(strategy, 7);
                assert_eq!(
                    balance.choose(first, Some(&a), None),
                    fallback.choose(first, Some(&a), None)
                );
                assert_eq!(
                    balance.choose(second, Some(&b), Some("")),
                    fallback.choose(second, Some(&b), None)
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn balance_strategies_health_stickiness_and_membership() {
        let source = Some("192.0.2.1:1234".parse().unwrap());
        let a = Destination::domain("a.example.co.uk", 443).unwrap();
        let b = Destination::domain("b.example.co.uk", 80).unwrap();
        let mut round = Balance::new(BalanceStrategy::RoundRobin, 3);
        assert_eq!(
            (0..4)
                .map(|_| round.choose(source, Some(&a), None))
                .collect::<Vec<_>>(),
            [0, 1, 2, 0]
        );
        round.health(&[None, Some(20), None]);
        assert_eq!(round.choose(source, Some(&a), None), 1);
        let mut hash = Balance::new(BalanceStrategy::ConsistentHashing, 3);
        assert_eq!(
            hash.choose(source, Some(&a), None),
            hash.choose(source, Some(&b), None)
        );
        let mut sticky = Balance::new(BalanceStrategy::StickySessions, 3);
        let index = sticky.choose(source, Some(&a), None);
        for _ in 0..20 {
            assert_eq!(sticky.choose(source, Some(&b), None), index);
        }
        tokio::time::advance(Duration::from_secs(601)).await;
        sticky.choose(source, Some(&a), None);
        assert!(sticky.sticky.values().all(|e| e.expires > Instant::now()));
        // A new provider generation owns its own state; an old transport keeps its leaf.
        let mut updated = Balance::new(BalanceStrategy::RoundRobin, 2);
        assert_eq!(
            (
                updated.choose(source, Some(&a), None),
                updated.choose(source, Some(&b), None)
            ),
            (0, 1)
        );
        assert_eq!(round.choose(source, Some(&a), None), 1);
    }
}
