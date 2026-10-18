//! Separate synthetic address pools; answer TTL does not expire the reverse map.
use crate::config::Network;
use crate::config::{
    DnsPolicySelector, FakeIpConfig, FakeIpFilterMode, FakeIpRange, RuleAction, RuleKind,
};
use crate::routing::{GeoMatcher, RoutingContext};
use crate::session::Destination;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
};

const MEMORY_ENTRIES: usize = 1000;
const RANGES: TableDefinition<&str, &str> = TableDefinition::new("ranges");
const OFFSETS: TableDefinition<&str, u128> = TableDefinition::new("offsets");
fn storage_error(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("fake-IP storage is unavailable")
}

pub(crate) struct DomainFilter {
    index: super::policy::DomainIndex,
    selectors: Vec<DnsPolicySelector>,
}
impl DomainFilter {
    pub(crate) fn new(selectors: &[DnsPolicySelector]) -> Self {
        let mut index = super::policy::DomainIndex::new();
        for selector in selectors {
            if let DnsPolicySelector::Domains(patterns) = selector {
                for pattern in patterns {
                    index.insert(pattern, 0);
                }
            }
        }
        Self {
            index,
            selectors: selectors.to_vec(),
        }
    }
    pub(crate) fn matches(
        &self,
        host: &str,
        geo: &dyn GeoMatcher,
        decision: &crate::config::RuleDecision,
    ) -> Result<bool, crate::config::MatchFailure> {
        decision.visit()?;
        if self.index.find(0, host).is_some() {
            return Ok(true);
        }
        for selector in &self.selectors {
            match selector {
                DnsPolicySelector::GeoSite(codes) => {
                    for code in codes {
                        if geo.geosite_available(code)
                            && geo.matches_geosite_bounded(code, host, decision)?
                        {
                            return Ok(true);
                        }
                    }
                }
                DnsPolicySelector::RuleSets { sets, .. } => {
                    for set in sets {
                        if set.matches_domain(host, geo, decision)? {
                            return Ok(true);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }
}
pub(crate) struct Filter {
    config: FakeIpConfig,
    domains: DomainFilter,
}
impl Filter {
    pub(crate) fn new(config: &FakeIpConfig) -> Self {
        Self {
            config: config.clone(),
            domains: DomainFilter::new(&config.filter),
        }
    }
    pub(crate) fn skips(
        &self,
        host: &str,
        geo: &dyn GeoMatcher,
        decision: &crate::config::RuleDecision,
    ) -> Result<bool, crate::config::MatchFailure> {
        decision.visit()?;
        if self.config.mode == FakeIpFilterMode::Rule {
            let destination = Destination::Domain {
                host: host.to_owned(),
                port: 53,
            };
            let Ok(context) = RoutingContext::new(Network::Tcp, &destination) else {
                return Ok(true);
            };
            let mut context = context.with_decision(decision);
            context.disable_ip_resolution();
            for rule in &self.config.rules {
                let matched = if let RuleKind::RuleSet {
                    content: Some(set), ..
                } = &rule.kind
                {
                    set.matches_domain(host, geo, decision)?
                } else {
                    match crate::routing::matches_rule(rule, &context, geo) {
                        Ok(matched) => matched,
                        Err(
                            crate::routing::PredicateFailure::NeedsIpResolution
                            | crate::routing::PredicateFailure::NeedsProcessLookup,
                        ) => false,
                        Err(crate::routing::PredicateFailure::Evaluation(failure)) => {
                            return Err(failure);
                        }
                    }
                };
                if matched {
                    return Ok(rule.action == RuleAction::Direct);
                }
            }
            return Ok(false);
        }
        let matched = self.domains.matches(host, geo, decision)?;
        Ok(if self.config.mode == FakeIpFilterMode::Whitelist {
            !matched
        } else {
            matched
        })
    }
}

pub(crate) struct FakePools {
    v4: Option<Mutex<Pool>>,
    v6: Option<Mutex<Pool>>,
}
impl FakePools {
    pub(crate) fn open(config: &FakeIpConfig, ipv6: bool, path: Option<&Path>) -> io::Result<Self> {
        let database = path
            .map(|path| {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
                Database::builder()
                    .set_cache_size(2 * 1024 * 1024)
                    .create_file(file)
                    .map(Arc::new)
                    .map_err(storage_error)
            })
            .transpose()?;
        Ok(Self {
            v4: config
                .range
                .map(|range| Pool::new(range, database.clone()))
                .transpose()?
                .map(Mutex::new),
            v6: config
                .range6
                .filter(|_| ipv6)
                .map(|range| Pool::new(range, database.clone()))
                .transpose()?
                .map(Mutex::new),
        })
    }
    pub(crate) fn lookup(&self, host: &str, ipv6: bool) -> io::Result<Option<IpAddr>> {
        let pool = if ipv6 { &self.v6 } else { &self.v4 };
        pool.as_ref()
            .map(|pool| pool.lock().map_err(storage_error)?.lookup(host))
            .transpose()
    }
    pub(crate) fn recover(&self, address: IpAddr) -> io::Result<Option<String>> {
        let pool = if address.is_ipv6() {
            &self.v6
        } else {
            &self.v4
        };
        let Some(pool) = pool else {
            return Ok(None);
        };
        let mut pool = pool.lock().map_err(storage_error)?;
        let (base, last) = pool.range.bounds();
        let value = ip_value(address);
        if !pool.range.cidr.contains(address) || value == base + 1 || value == last {
            return Ok(None);
        }
        pool.reverse(value)?.map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "fake-IP mapping is no longer available",
            )
        })
    }
}
fn ip_value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    }
}
struct Pool {
    range: FakeIpRange,
    next: u128,
    database: Option<Arc<Database>>,
    family: &'static str,
    hosts: TableDefinition<'static, &'static str, u128>,
    ips: TableDefinition<'static, u128, &'static str>,
    memory: HashMap<String, (u128, u64)>,
    reverse: HashMap<u128, String>,
    clock: u64,
}
impl Pool {
    fn new(range: FakeIpRange, database: Option<Arc<Database>>) -> io::Result<Self> {
        let ipv6 = range.cidr.network.is_ipv6();
        let family = if ipv6 { "6" } else { "4" };
        let hosts = TableDefinition::new(if ipv6 { "host6" } else { "host4" });
        let ips = TableDefinition::new(if ipv6 { "ip6" } else { "ip4" });
        let mut next = range.bounds().0 + 3;
        if let Some(db) = &database {
            let tx = db.begin_write().map_err(storage_error)?;
            {
                let mut ranges = tx.open_table(RANGES).map_err(storage_error)?;
                let key = format!("{}/{}", range.cidr.network, range.cidr.prefix_len);
                let same = ranges
                    .get(family)
                    .map_err(storage_error)?
                    .is_some_and(|v| v.value() == key);
                let mut offsets = tx.open_table(OFFSETS).map_err(storage_error)?;
                if !same {
                    tx.delete_table(hosts).map_err(storage_error)?;
                    tx.delete_table(ips).map_err(storage_error)?;
                    ranges.insert(family, key.as_str()).map_err(storage_error)?;
                    offsets.insert(family, next).map_err(storage_error)?;
                } else if let Some(value) = offsets.get(family).map_err(storage_error)? {
                    next = value.value();
                }
                tx.open_table(hosts).map_err(storage_error)?;
                tx.open_table(ips).map_err(storage_error)?;
            }
            tx.commit().map_err(storage_error)?;
        }
        let (base, last) = range.bounds();
        if next < base + 3 || next >= last {
            return Err(storage_error("invalid offset"));
        }
        Ok(Self {
            range,
            next,
            database,
            family,
            hosts,
            ips,
            memory: HashMap::new(),
            reverse: HashMap::new(),
            clock: 0,
        })
    }
    fn lookup(&mut self, host: &str) -> io::Result<IpAddr> {
        self.clock = self.clock.wrapping_add(1);
        let previous = if let Some(db) = &self.database {
            let tx = db.begin_read().map_err(storage_error)?;
            let hosts = tx.open_table(self.hosts).map_err(storage_error)?;
            hosts.get(host).map_err(storage_error)?.map(|v| v.value())
        } else {
            self.memory.get_mut(host).map(|entry| {
                entry.1 = self.clock;
                entry.0
            })
        };
        if let Some(value) = previous {
            return Ok(self.range.address(value));
        }
        let (base, last) = self.range.bounds();
        let mut next = self.next + 1;
        if next >= last {
            next = base + 4;
        }
        if let Some(db) = &self.database {
            let tx = db.begin_write().map_err(storage_error)?;
            {
                let mut hosts = tx.open_table(self.hosts).map_err(storage_error)?;
                let mut ips = tx.open_table(self.ips).map_err(storage_error)?;
                let previous = ips
                    .remove(next)
                    .map_err(storage_error)?
                    .map(|v| v.value().to_owned());
                if let Some(previous) = previous {
                    hosts.remove(previous.as_str()).map_err(storage_error)?;
                }
                hosts.insert(host, next).map_err(storage_error)?;
                ips.insert(next, host).map_err(storage_error)?;
                tx.open_table(OFFSETS)
                    .map_err(storage_error)?
                    .insert(self.family, next)
                    .map_err(storage_error)?;
            }
            tx.commit().map_err(storage_error)?;
        } else {
            if let Some(previous) = self.reverse.remove(&next) {
                self.memory.remove(&previous);
            }
            if self.memory.len() >= MEMORY_ENTRIES
                && let Some(old) = self
                    .memory
                    .iter()
                    .min_by_key(|(_, (_, clock))| clock)
                    .map(|(host, _)| host.clone())
            {
                let (address, _) = self.memory.remove(&old).unwrap();
                self.reverse.remove(&address);
            }
            self.memory.insert(host.to_owned(), (next, self.clock));
            self.reverse.insert(next, host.to_owned());
        }
        self.next = next;
        Ok(self.range.address(next))
    }
    fn reverse(&mut self, ip: u128) -> io::Result<Option<String>> {
        self.clock = self.clock.wrapping_add(1);
        if let Some(db) = &self.database {
            let tx = db.begin_read().map_err(storage_error)?;
            let ips = tx.open_table(self.ips).map_err(storage_error)?;
            ips.get(ip)
                .map_err(storage_error)
                .map(|v| v.map(|v| v.value().to_owned()))
        } else {
            let host = self.reverse.get(&ip).cloned();
            if let Some(entry) = host.as_ref().and_then(|host| self.memory.get_mut(host)) {
                entry.1 = self.clock;
            }
            Ok(host)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fake_ip_persistence_restarts_and_reuses_addresses_transactionally() {
        let mut config = crate::config::DnsConfig::default().fake_ip;
        config.range = FakeIpRange::parse("198.18.0.1/29", false).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fake-ip.redb");
        let first;
        {
            let pools = FakePools::open(&config, false, Some(&path)).unwrap();
            first = pools.lookup("one.example", false).unwrap().unwrap();
            assert_eq!(first, "198.18.0.4".parse::<IpAddr>().unwrap());
            pools.lookup("two.example", false).unwrap();
        }
        {
            let pools = FakePools::open(&config, false, Some(&path)).unwrap();
            assert_eq!(
                pools.recover(first).unwrap().as_deref(),
                Some("one.example")
            );
            assert_eq!(pools.lookup("one.example", false).unwrap(), Some(first));
            assert_eq!(
                pools.lookup("three.example", false).unwrap(),
                Some("198.18.0.6".parse().unwrap())
            );
            assert_eq!(pools.lookup("four.example", false).unwrap(), Some(first));
            assert_eq!(
                pools.recover(first).unwrap().as_deref(),
                Some("four.example")
            );
        }
        config.range = FakeIpRange::parse("198.19.0.1/29", false).unwrap();
        let pools = FakePools::open(&config, false, Some(&path)).unwrap();
        assert_eq!(pools.recover(first).unwrap(), None);
        assert_eq!(
            pools.lookup("one.example", false).unwrap(),
            Some("198.19.0.4".parse().unwrap())
        );
    }
}
