//! Child of linux_tun: read addresses in the borrowed TUN's owning namespace.
use super::*;
use crate::config::IpCidr;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
const ADDRESS_HEADER: usize = 8;
const MAX_PREFIXES: usize = 64;
const MAX_DUMP_BYTES: usize = 1024 * 1024;

pub(crate) fn interface_prefixes(fd: BorrowedFd<'_>) -> io::Result<Vec<IpCidr>> {
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
        return Err(os_error("Linux TUN Echo interface query"));
    }
    validate_flags(unsafe { request.ifr_ifru.ifru_flags } as u16)?;
    if request.ifr_name[0] == 0 || !request.ifr_name.contains(&0) {
        return Err(invalid("Linux TUN Echo interface name is invalid"));
    }
    let namespace_fd = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETDEVNETNS) };
    if namespace_fd < 0 {
        return Err(os_error("Linux TUN Echo namespace query"));
    }
    let namespace = File::from(unsafe { OwnedFd::from_raw_fd(namespace_fd) });
    let target = namespace.metadata()?;
    let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
    let name = request.ifr_name;
    if target.dev() == current.dev() && target.ino() == current.ino() {
        return address_snapshot(name);
    }
    // Same disposable-thread namespace boundary as borrowed-fd validation.
    thread::Builder::new()
        .name("vole-tun-echo-prefix".into())
        .spawn(move || {
            if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
                return Err(os_error("Linux TUN Echo namespace entry"));
            }
            address_snapshot(name)
        })?
        .join()
        .map_err(|_| io::Error::other("TUN Echo prefix worker panicked"))?
}
fn address_snapshot(name: [libc::c_char; libc::IFNAMSIZ]) -> io::Result<Vec<IpCidr>> {
    let control = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name = name;
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFINDEX, &mut request) } < 0 {
        return Err(os_error("Linux TUN Echo interface index"));
    }
    let index = unsafe { request.ifr_ifru.ifru_ifindex };
    if index <= 0 {
        return Err(invalid("Linux TUN Echo interface index is invalid"));
    }
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast(),
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } < 0
        {
            return Err(os_error("Linux TUN Echo address query timeout"));
        }
    }
    let mut query = [0u8; NETLINK_HEADER + ADDRESS_HEADER];
    let len = query.len() as u32;
    query[..4].copy_from_slice(&len.to_ne_bytes());
    query[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
    query[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    query[8..12].copy_from_slice(&QUERY_SEQUENCE.to_ne_bytes());
    query[NETLINK_HEADER] = libc::AF_UNSPEC as u8;
    query[NETLINK_HEADER + 4..NETLINK_HEADER + 8].copy_from_slice(&index.to_ne_bytes());
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            query.as_ptr().cast(),
            query.len(),
            0,
            (&raw const kernel).cast(),
            std::mem::size_of_val(&kernel) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(os_error("Linux TUN Echo address query"));
    }
    if sent as usize != query.len() {
        return Err(invalid("short Linux TUN address query"));
    }
    let mut buffer = [0u8; 32768];
    let mut total = 0usize;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut prefixes = Vec::with_capacity(MAX_PREFIXES);
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut peer = kernel;
        let mut peer_len = std::mem::size_of_val(&peer) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&raw mut peer).cast(),
                &mut peer_len,
            )
        };
        if n < 0 {
            return Err(os_error("Linux TUN Echo address response"));
        }
        total = total.saturating_add(n as usize);
        if n == 0
            || n as usize > buffer.len()
            || total > MAX_DUMP_BYTES
            || peer_len as usize != std::mem::size_of_val(&peer)
            || peer.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || peer.nl_pid != 0
            || peer.nl_groups != 0
        {
            return Err(invalid(
                "Linux TUN Echo address response is invalid or oversized",
            ));
        }
        let mut messages = &buffer[..n as usize];
        while !messages.is_empty() {
            if messages.len() < NETLINK_HEADER {
                return Err(invalid("short TUN address message"));
            }
            let len = native_u32(&messages[..4])? as usize;
            let aligned = (len + 3) & !3;
            if len < NETLINK_HEADER
                || aligned > messages.len()
                || native_u32(&messages[8..12])? != QUERY_SEQUENCE
                || native_u16(&messages[6..8])? & 0x10 != 0
            {
                // NLM_F_DUMP_INTR
                return Err(invalid("interrupted or malformed TUN address dump"));
            }
            let body = &messages[NETLINK_HEADER..len];
            match i32::from(native_u16(&messages[4..6])?) {
                libc::NLMSG_DONE => {
                    if body.len() >= 4 && i32::from_ne_bytes(body[..4].try_into().unwrap()) != 0 {
                        return Err(invalid("TUN address dump completion reported an error"));
                    }
                    return Ok(prefixes);
                }
                libc::NLMSG_ERROR => {
                    if body.len() < 4 {
                        return Err(invalid("short TUN address errno"));
                    }
                    let errno = i32::from_ne_bytes(body[..4].try_into().unwrap());
                    if errno < 0 && errno != i32::MIN {
                        return Err(io::Error::from_raw_os_error(-errno));
                    }
                    if errno != 0 {
                        return Err(invalid("invalid TUN address errno"));
                    }
                }
                kind if kind == i32::from(libc::RTM_NEWADDR) => {
                    if body.len() < ADDRESS_HEADER {
                        return Err(invalid("short TUN address header"));
                    }
                    if native_u32(&body[4..8])? == index as u32 {
                        let attrs = &body[ADDRESS_HEADER..];
                        let address = match i32::from(body[0]) {
                            libc::AF_INET if body[1] <= 32 => {
                                let local = attribute(attrs, libc::IFA_LOCAL)?
                                    .or(attribute(attrs, libc::IFA_ADDRESS)?);
                                local
                                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                                    .map(Ipv4Addr::from)
                                    .map(IpAddr::V4)
                            }
                            libc::AF_INET6 if body[1] <= 128 => {
                                attribute(attrs, libc::IFA_ADDRESS)?
                                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                                    .map(Ipv6Addr::from)
                                    .map(IpAddr::V6)
                            }
                            _ => None,
                        }
                        .ok_or_else(|| invalid("invalid TUN interface address"))?;
                        let prefix = IpCidr {
                            network: address,
                            prefix_len: body[1],
                        };
                        if !prefixes.contains(&prefix) {
                            if prefixes.len() == MAX_PREFIXES {
                                return Err(invalid("too many TUN interface prefixes"));
                            }
                            prefixes.push(prefix);
                        }
                    }
                }
                _ => {}
            }
            messages = &messages[aligned..];
        }
    }
}
