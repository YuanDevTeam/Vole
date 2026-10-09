//! Per-group selection; transports retain the selected leaf, not this cursor.
use crate::{config::BalanceStrategy, session::Destination};
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
            healthy: vec![true; members],
            cursor: 0,
            sticky: HashMap::new(),
            clock: 0,
        }
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
                self.cursor = (index + 1) % count;
                return index;
            }
            return 0;
        }
        let mut key = destination_key(destination);
        if self.strategy == BalanceStrategy::StickySessions {
            key.insert_str(
                0,
                &source.map_or_else(|| "invalid IP".into(), |s| s.ip().to_string()),
            );
        }
        static HASH: OnceLock<RandomState> = OnceLock::new();
        let key = HASH.get_or_init(RandomState::new).hash_one(key);
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
        let index = (0..4)
            .map(|_| jump(key.wrapping_add(rand::random::<u64>()), count))
            .find(|&i| self.healthy[i])
            .unwrap_or(0);
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
    #[tokio::test(start_paused = true)]
    async fn balance_strategies_health_stickiness_and_membership() {
        let source = Some("192.0.2.1:1234".parse().unwrap());
        let a = Destination::domain("a.example.co.uk", 443).unwrap();
        let b = Destination::domain("b.example.co.uk", 80).unwrap();
        let mut round = Balance::new(BalanceStrategy::RoundRobin, 3);
        assert_eq!(
            (0..4)
                .map(|_| round.choose(source, Some(&a)))
                .collect::<Vec<_>>(),
            [0, 1, 2, 0]
        );
        round.health(&[None, Some(20), None]);
        assert_eq!(round.choose(source, Some(&a)), 1);
        let mut hash = Balance::new(BalanceStrategy::ConsistentHashing, 3);
        assert_eq!(hash.choose(source, Some(&a)), hash.choose(source, Some(&b)));
        let mut sticky = Balance::new(BalanceStrategy::StickySessions, 3);
        let index = sticky.choose(source, Some(&a));
        for _ in 0..20 {
            assert_eq!(sticky.choose(source, Some(&b)), index);
        }
        tokio::time::advance(Duration::from_secs(601)).await;
        sticky.choose(source, Some(&a));
        assert!(sticky.sticky.values().all(|e| e.expires > Instant::now()));
        // A new provider generation owns its own state; an old transport keeps its leaf.
        let mut updated = Balance::new(BalanceStrategy::RoundRobin, 2);
        assert_eq!(
            (
                updated.choose(source, Some(&a)),
                updated.choose(source, Some(&b))
            ),
            (0, 1)
        );
        assert_eq!(round.choose(source, Some(&a)), 1);
    }
}
