//! Transactional system network changes for one core-owned Linux TUN.
use std::io;

mod plan;
use plan::{Route, Rule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Change {
    Route(Route),
    Rule(Rule),
    DnsServers,
    DnsDomains,
    DnsDefaultRoute,
}

pub(crate) trait Backend {
    fn apply(&mut self, change: &Change) -> io::Result<()>;
    fn remove(&mut self, change: &Change) -> io::Result<()>;
}

pub(crate) struct Lease<B: Backend> {
    backend: B,
    applied: Vec<Change>,
}
impl<B: Backend> Lease<B> {
    fn new(backend: B) -> Self {
        Self {
            backend,
            applied: Vec::new(),
        }
    }
    fn apply(&mut self, change: Change) -> io::Result<()> {
        self.backend.apply(&change)?;
        self.applied.push(change);
        Ok(())
    }
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        let mut error = None;
        while let Some(change) = self.applied.pop() {
            if let Err(failure) = self.backend.remove(&change) {
                error.get_or_insert(failure);
            }
        }
        error.map_or(Ok(()), Err)
    }
}
impl<B: Backend> Drop for Lease<B> {
    fn drop(&mut self) {
        if self.restore().is_err() {
            tracing::error!("Linux network cleanup failed");
        }
    }
}

#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "linux")]
pub(crate) use native::{LinuxBackend, SocketPolicy, open};
#[cfg(target_os = "linux")]
pub(crate) type NetworkLease = Lease<LinuxBackend>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    struct Mock {
        events: Arc<Mutex<Vec<(bool, Change)>>>,
        fail: Option<Change>,
    }
    impl Backend for Mock {
        fn apply(&mut self, change: &Change) -> io::Result<()> {
            if self.fail.as_ref() == Some(change) {
                return Err(io::Error::other("fixture"));
            }
            self.events.lock().unwrap().push((true, change.clone()));
            Ok(())
        }
        fn remove(&mut self, change: &Change) -> io::Result<()> {
            self.events.lock().unwrap().push((false, change.clone()));
            Ok(())
        }
    }
    #[test]
    fn failed_start_and_normal_stop_restore_only_completed_changes_in_reverse() {
        let changes = [
            Change::Route(Route {
                ipv6: false,
                index: 7,
                table: 2022,
                destination: crate::config::IpCidr {
                    network: "0.0.0.0".parse().unwrap(),
                    prefix_len: 0,
                },
            }),
            Change::Rule(Rule {
                ipv6: false,
                priority: 9000,
                selector: plan::Selector::Local,
                action: plan::Action::MainNonDefault,
            }),
            Change::Rule(Rule {
                ipv6: false,
                priority: 9001,
                selector: plan::Selector::Local,
                action: plan::Action::Table(2022),
            }),
            Change::DnsServers,
            Change::DnsDomains,
            Change::DnsDefaultRoute,
        ];
        for fail_at in 0..=changes.len() {
            let events = Arc::new(Mutex::new(Vec::new()));
            {
                let mut lease = Lease::new(Mock {
                    events: events.clone(),
                    fail: changes.get(fail_at).cloned(),
                });
                for change in &changes {
                    if lease.apply(change.clone()).is_err() {
                        break;
                    }
                }
                if fail_at == changes.len() {
                    lease.restore().unwrap();
                    lease.restore().unwrap();
                }
            }
            let events = events.lock().unwrap();
            let expected: Vec<_> = changes[..fail_at]
                .iter()
                .cloned()
                .map(|c| (true, c))
                .chain(changes[..fail_at].iter().rev().cloned().map(|c| (false, c)))
                .collect();
            assert_eq!(*events, expected);
        }
    }
}
