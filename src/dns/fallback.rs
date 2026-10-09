use crate::{config::DnsFallbackConfig, routing::GeoMatcher};
use std::{future::Future, net::IpAddr};

pub(crate) struct Filter {
    config: DnsFallbackConfig,
    domains: super::fake_ip::DomainFilter,
}
impl Filter {
    pub(crate) fn new(config: &DnsFallbackConfig) -> Self {
        Self {
            config: config.clone(),
            domains: super::fake_ip::DomainFilter::new(&config.domains),
        }
    }
    pub(crate) fn domain(&self, host: &str, geo: &dyn GeoMatcher) -> bool {
        self.domains.matches(host, geo)
    }
    pub(crate) fn address(&self, address: IpAddr, geo: &dyn GeoMatcher) -> bool {
        if self.config.ipcidr.iter().any(|cidr| cidr.contains(address)) {
            return true;
        }
        let Some(code) = &self.config.geoip else {
            return false;
        };
        let local = address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || match address {
                IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
                IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
            };
        !local
            && (code == "lan" || (geo.geoip_available(code) && !geo.matches_geoip(code, address)))
    }
}

// Both futures remain owned by the requesting DNS flight. Returning the primary
// drops the speculative fallback; cancellation drops both without detached work.
pub(super) async fn choose<T>(
    primary: impl Future<Output = T>,
    fallback: impl Future<Output = T>,
    lazy: bool,
    acceptable: impl FnOnce(&T) -> bool,
) -> T {
    tokio::pin!(fallback);
    let mut ready = None;
    let first = if lazy {
        primary.await
    } else {
        tokio::pin!(primary);
        tokio::select! {
            biased;
            answer = &mut fallback => { ready = Some(answer); primary.await }
            answer = &mut primary => answer,
        }
    };
    if acceptable(&first) {
        first
    } else if let Some(answer) = ready {
        answer
    } else {
        fallback.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    #[tokio::test]
    async fn fallback_query_scheduling_cancels_speculation_and_defers_lazy_work() {
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for lazy in [true, false] {
            let started = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicBool::new(false));
            let fallback = {
                let started = started.clone();
                let dropped = dropped.clone();
                async move {
                    started.store(true, Ordering::SeqCst);
                    let _guard = Guard(dropped);
                    std::future::pending::<u8>().await
                }
            };
            assert_eq!(choose(async { 1 }, fallback, lazy, |v| *v == 1).await, 1);
            assert_eq!(started.load(Ordering::SeqCst), !lazy);
            assert_eq!(dropped.load(Ordering::SeqCst), !lazy);
        }
        assert_eq!(choose(async { 0 }, async { 2 }, true, |v| *v == 1).await, 2);
    }
    #[test]
    fn fallback_geoip_preserves_local_addresses_and_uses_shared_matcher() {
        struct Country;
        impl GeoMatcher for Country {
            fn matches_geosite(&self, _: &str, _: &str) -> bool {
                false
            }
            fn geoip_available(&self, code: &str) -> bool {
                code == "cn"
            }
            fn matches_geoip(&self, _: &str, address: IpAddr) -> bool {
                address == "203.0.113.1".parse::<IpAddr>().unwrap()
            }
        }
        let filter = Filter::new(&DnsFallbackConfig {
            geoip: Some("cn".into()),
            ..Default::default()
        });
        for address in [
            "10.1.2.3",
            "127.0.0.1",
            "169.254.0.2",
            "::1",
            "fc00::1",
            "203.0.113.1",
        ] {
            assert!(!filter.address(address.parse().unwrap(), &Country));
        }
        assert!(filter.address("203.0.113.2".parse().unwrap(), &Country));
        assert!(!filter.address(
            "203.0.113.2".parse().unwrap(),
            &crate::routing::EmptyGeoMatcher
        ));
    }
}
