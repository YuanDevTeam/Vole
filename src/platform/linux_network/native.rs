use super::{
    Backend, Change, Lease, NetworkLease, netlink,
    plan::{Plan, Route},
};
use crate::{
    config::{DnsConfig, TunConfig},
    dialer::Dialer,
    platform::TunIo,
};
use std::{
    ffi::CString,
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Interfaces {
    refreshed: Instant,
    ipv4: Option<String>,
    ipv6: Option<String>,
}
pub(crate) struct SocketPolicy {
    detect: bool,
    mark: bool,
    interfaces: Mutex<Option<Interfaces>>,
}
impl SocketPolicy {
    fn default_mark(&self, configured_mark: u32) -> Option<u32> {
        // Every capture rule matches only mark zero. A nonzero public mark
        // already bypasses this lease and must retain its own RPDB meaning.
        (self.mark && configured_mark == 0).then_some(netlink::MARK)
    }
    fn new(detect: bool, mark: bool) -> Self {
        Self {
            detect,
            mark,
            interfaces: Mutex::new(None),
        }
    }
    pub(crate) fn apply(
        &self,
        socket: &impl AsRawFd,
        destination: SocketAddr,
        configured_mark: u32,
    ) -> io::Result<()> {
        self.apply_with_interface(socket, destination, configured_mark, None)
    }
    pub(crate) fn apply_with_interface(
        &self,
        socket: &impl AsRawFd,
        destination: SocketAddr,
        configured_mark: u32,
        interface: Option<&str>,
    ) -> io::Result<()> {
        if let Some(value) = self.default_mark(configured_mark) {
            // SAFETY: socket is live and the option points to a u32 mark.
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&raw const value).cast(),
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        if let Some(interface) = interface {
            let name = CString::new(interface).map_err(|_| io::ErrorKind::InvalidInput)?;
            // SAFETY: live socket, terminated interface name and a u32 index.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::ErrorKind::NotFound.into());
            }
            if let SocketAddr::V6(address) = destination
                && address.scope_id() != 0
                && address.scope_id() != index
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            // SAFETY: name remains live and socket is owned by its initializer.
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name.as_ptr().cast(),
                    name.as_bytes_with_nul().len() as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
        if !self.detect || destination.ip().is_loopback() {
            return Ok(());
        }
        let mut state = self
            .interfaces
            .lock()
            .map_err(|_| io::Error::other("Linux egress state unavailable"))?;
        if state
            .as_ref()
            .is_none_or(|state| state.refreshed.elapsed() >= Duration::from_secs(1))
        {
            *state = Some(Interfaces {
                ipv4: netlink::default_interface(false)?,
                ipv6: netlink::default_interface(true)?,
                refreshed: Instant::now(),
            });
        }
        let state = state.as_ref().unwrap();
        let interface = if destination.is_ipv6() {
            &state.ipv6
        } else {
            &state.ipv4
        };
        let name = CString::new(
            interface
                .as_ref()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "no physical default interface for address family",
                    )
                })?
                .as_str(),
        )
        .map_err(|_| io::Error::other("invalid Linux interface"))?;
        // SAFETY: name is NUL terminated and socket is still owned by its initializer.
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast(),
                name.as_bytes_with_nul().len() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(crate) struct LinuxBackend {
    name: String,
    // Keep the newly created interface alive until DNS and routing cleanup ends.
    _tun_owner: OwnedFd,
    dns_reverted: bool,
    dns_server: String,
}
impl LinuxBackend {
    fn resolved(&self, operation: &str, values: &[&str]) -> io::Result<()> {
        let mut child = Command::new("/usr/bin/resolvectl")
            .arg("--no-ask-password")
            .arg(operation)
            .arg(&self.name)
            .args(values)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Linux DNS takeover requires systemd-resolved and resolvectl",
                )
            })?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Linux per-link DNS setup failed; check installed resolve1 authorization",
                        ))
                    };
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(result.err().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::TimedOut, "Linux DNS configuration timed out")
                    }));
                }
            }
        }
    }
}
impl Backend for LinuxBackend {
    fn apply(&mut self, change: &Change) -> io::Result<()> {
        match change {
            Change::DnsServers => self.resolved("dns", &[&self.dns_server]),
            Change::DnsDomains => self.resolved("domain", &["~."]),
            Change::DnsDefaultRoute => self.resolved("default-route", &["yes"]),
            other => netlink::change(other, true),
        }
    }
    fn remove(&mut self, change: &Change) -> io::Result<()> {
        match change {
            Change::DnsServers | Change::DnsDomains | Change::DnsDefaultRoute => {
                if self.dns_reverted {
                    return Ok(());
                }
                self.resolved("revert", &[])?;
                self.dns_reverted = true;
                Ok(())
            }
            other => match netlink::change(other, false) {
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOENT | libc::ESRCH | libc::ENODEV)
                    ) =>
                {
                    Ok(())
                }
                result => result,
            },
        }
    }
}

pub(crate) fn open(
    config: &TunConfig,
    dns: &DnsConfig,
    ipv6: bool,
    dialer: Dialer,
) -> io::Result<(TunIo, Dialer, Option<NetworkLease>)> {
    if !config.auto_route && !config.auto_detect_interface {
        return Ok((
            TunIo::open(&config.device, config.mtu).map_err(io::Error::other)?,
            dialer,
            None,
        ));
    }
    let dialer = dialer.with_linux_policy(Arc::new(SocketPolicy::new(
        config.auto_detect_interface,
        config.auto_route,
    )));
    if !config.auto_route {
        return Ok((
            TunIo::open(&config.device, config.mtu).map_err(io::Error::other)?,
            dialer,
            None,
        ));
    }
    // Plan and collision checks precede creating any interface or network object.
    let plan = Plan::new(config, ipv6)?;
    for family in [false, true] {
        if !family || plan.ipv6 || config.network.strict_route {
            netlink::ensure_available(
                family,
                config.network.table_index,
                config.network.rule_index,
            )?;
        }
    }
    let tun = TunIo::open_exclusive(&config.device, config.mtu).map_err(io::Error::other)?;
    let device = tun.linux_device();
    let name = device.name()?;
    let c_name =
        CString::new(name.as_str()).map_err(|_| io::Error::other("invalid Linux TUN name"))?;
    // SAFETY: name is a valid terminated device name.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: duplicate preserves ownership while cleanup runs after the reader exits.
    let owner = unsafe { libc::fcntl(device.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if owner < 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = unsafe { OwnedFd::from_raw_fd(owner) };
    let address = dns
        .fake_ip
        .range
        .map(|range| range.interface_address)
        .unwrap_or("198.18.0.1".parse().unwrap());
    let std::net::IpAddr::V4(address) = address else {
        unreachable!("validated IPv4 range")
    };
    let dns_address = std::net::Ipv4Addr::from(
        u32::from(address)
            .checked_add(1)
            .ok_or_else(|| io::Error::other("TUN DNS address is outside IPv4"))?,
    );
    let mut lease = Lease::new(LinuxBackend {
        name,
        _tun_owner: owner,
        dns_reverted: false,
        dns_server: dns_address.to_string(),
    });
    device.set_network_address(address, 30, None::<std::net::Ipv4Addr>)?;
    if plan.ipv6 {
        for address in &config.network.inet6_address {
            device.add_address_v6(address.address, address.prefix_len)?;
        }
    }
    device.enabled(true)?;
    for destination in plan.routes {
        lease.apply(Change::Route(Route {
            ipv6: destination.network.is_ipv6(),
            index,
            table: config.network.table_index,
            destination,
        }))?;
    }
    for rule in plan.rules {
        lease.apply(Change::Rule(rule))?;
    }
    if dns.enable && config.hijacks_dns(SocketAddr::new(dns_address.into(), 53)) {
        lease.apply(Change::DnsServers)?;
        lease.apply(Change::DnsDomains)?;
        lease.apply(Change::DnsDefaultRoute)?;
    }
    Ok((tun, dialer, Some(lease)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_route_injects_only_a_default_mark_and_preserves_public_marks() {
        for detect in [false, true] {
            let protected = SocketPolicy::new(detect, true);
            assert_eq!(protected.default_mark(0), Some(netlink::MARK));
            for mark in [1, 7, 42, netlink::MARK, u32::MAX] {
                assert_eq!(protected.default_mark(mark), None);
            }
            let unmanaged = SocketPolicy::new(detect, false);
            for mark in [0, 1, netlink::MARK, u32::MAX] {
                assert_eq!(unmanaged.default_mark(mark), None);
            }
            // Loopback callers deliberately pass zero rather than the public
            // mark, keeping local proxies on the existing private bypass.
            assert_eq!(protected.default_mark(0), Some(netlink::MARK));
        }
    }
}
