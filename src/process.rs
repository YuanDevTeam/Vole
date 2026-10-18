//! Bounded, exact socket-owner discovery. No cache, shell or privilege changes.
use crate::{config::Network, session::InboundSnapshot};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct Identity {
    pub uid: Option<u32>,
    pub name: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("known_uid", &self.uid.is_some())
            .field("known_process", &self.path.is_some())
            .finish()
    }
}
impl Identity {
    fn from_path(path: String) -> Option<Self> {
        if path.is_empty() || path.len() > MAX_PATH || path.contains('\0') {
            return None;
        }
        let name = std::path::Path::new(&path).file_name()?.to_str()?;
        Some(Self {
            uid: None,
            name: Some(Arc::from(name)),
            path: Some(Arc::from(path)),
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Query {
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}
impl Query {
    pub fn from_snapshot(network: Network, origin: &InboundSnapshot) -> Option<Self> {
        let destination = origin.socket_destination?;
        if origin.source.is_ipv4() != destination.is_ipv4()
            || origin.source.ip().is_unspecified()
            || destination.ip().is_unspecified()
            || origin.source.port() == 0
            || destination.port() == 0
        {
            return None;
        }
        Some(Self {
            network,
            source: origin.source,
            destination,
        })
    }
}
const MAX_PATH: usize = 32 * 1024;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    all(windows, any(feature = "windows-uwp", feature = "windows-wintun"))
))]
const MAX_TABLE: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 16_384;
pub(crate) const LOOKUP_TIME: Duration = Duration::from_millis(100);
struct Budget<'a> {
    check: &'a dyn Fn() -> io::Result<()>,
    until: Instant,
    entries: usize,
}
impl Budget<'_> {
    fn check(&self) -> io::Result<()> {
        (self.check)()?;
        if Instant::now() >= self.until {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process lookup budget exhausted",
            ))
        } else {
            Ok(())
        }
    }
    fn visit(&mut self) -> io::Result<()> {
        self.check()?;
        self.entries = self
            .entries
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("process lookup scan exhausted"))?;
        Ok(())
    }
}
pub(crate) fn lookup(query: Query, check: &dyn Fn() -> io::Result<()>) -> io::Result<Identity> {
    let mut budget = Budget {
        check,
        until: Instant::now() + LOOKUP_TIME,
        entries: MAX_ENTRIES,
    };
    budget.check()?;
    platform(query, &mut budget)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "process/linux.rs"]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
use linux::platform;
#[cfg(target_os = "macos")]
#[path = "process/macos.rs"]
mod macos;
#[cfg(target_os = "macos")]
use macos::platform;
#[cfg(all(windows, any(feature = "windows-uwp", feature = "windows-wintun")))]
#[path = "process/windows.rs"]
mod windows;
#[cfg(all(windows, any(feature = "windows-uwp", feature = "windows-wintun")))]
use windows::platform;
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    all(windows, any(feature = "windows-uwp", feature = "windows-wintun"))
)))]
fn platform(_: Query, _: &mut Budget<'_>) -> io::Result<Identity> {
    Ok(Identity::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_uses_preserved_ingress_tuple_not_sniff_or_proxy_target() {
        let mut session = crate::session::StreamSession {
            metadata: crate::session::InboundMetadata::new(443),
            inbound: crate::session::InboundKind::Tun,
            source: "198.18.0.2:1234".parse().unwrap(),
            destination: crate::session::Destination::Ip("192.0.2.3:443".parse().unwrap()),
            sniffed_domain: None,
        };
        session.capture_original();
        let origin = session.metadata.original.clone().unwrap();
        session.destination = crate::session::Destination::domain("sniff.example", 443).unwrap();
        session.capture_original();
        assert!(Arc::ptr_eq(
            &origin,
            session.metadata.original.as_ref().unwrap()
        ));
        assert_eq!(
            Query::from_snapshot(Network::Tcp, &origin)
                .unwrap()
                .destination,
            "192.0.2.3:443".parse::<SocketAddr>().unwrap()
        );
        session.metadata.original = None;
        session.metadata.local_address = Some("127.0.0.1:1080".parse().unwrap());
        session.inbound = crate::session::InboundKind::Https;
        session.capture_original();
        assert_eq!(
            Query::from_snapshot(Network::Tcp, session.metadata.original.as_ref().unwrap())
                .unwrap()
                .destination
                .port(),
            1080
        );
        assert!(!format!("{origin:?}").contains("192.0.2"));
    }
    #[test]
    fn inspection_budget_is_bounded_and_cancelled_before_platform_access() {
        let query = Query {
            network: Network::Tcp,
            source: "127.0.0.1:1".parse().unwrap(),
            destination: "127.0.0.1:2".parse().unwrap(),
        };
        assert!(
            lookup(query, &|| Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled"
            )))
            .is_err()
        );
        let mut budget = Budget {
            check: &|| Ok(()),
            until: Instant::now() + LOOKUP_TIME,
            entries: 1,
        };
        budget.visit().unwrap();
        assert!(budget.visit().is_err());
    }
}
