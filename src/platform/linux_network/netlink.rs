//! Minimal bounded rtnetlink requests. Constants and layouts follow Linux UAPI.
use super::{
    Change,
    plan::{Action, Selector},
};
use std::{
    ffi::CStr,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
pub(super) const MARK: u32 = 0x564f4c45;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const CREATE_EXCL: u16 = 0x600;
const DUMP: u16 = 0x300;
const GET_ROUTE: u16 = 26;
const NEW_ROUTE: u16 = 24;
const DEL_ROUTE: u16 = 25;
const GET_RULE: u16 = 34;
const NEW_RULE: u16 = 32;
const DEL_RULE: u16 = 33;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Linux route response")
}
fn u32_at(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(bytes.try_into().map_err(|_| invalid())?))
}
fn attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize((out.len() + 3) & !3, 0);
}
fn attribute(mut bytes: &[u8], kind: u16) -> io::Result<Option<&[u8]>> {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid());
        }
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let aligned = (length + 3) & !3;
        if length < 4 || aligned > bytes.len() {
            return Err(invalid());
        }
        if u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff == kind {
            if found.is_some() {
                return Err(invalid());
            }
            found = Some(&bytes[4..length]);
        }
        bytes = &bytes[aligned..];
    }
    Ok(found)
}
fn property(bytes: &[u8], kind: u16, default: u32) -> io::Result<u32> {
    attribute(bytes, kind)?.map_or(Ok(default), u32_at)
}

fn exchange(kind: u16, flags: u16, payload: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    // SAFETY: successful socket returns a fresh owned descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let limit = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        // SAFETY: limit is a valid timeval and fd remains owned.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const limit).cast(),
                std::mem::size_of_val(&limit) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let mut request = vec![0; 16];
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&(flags | REQUEST).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request.extend_from_slice(payload);
    let length = request.len() as u32;
    request[..4].copy_from_slice(&length.to_ne_bytes());
    // SAFETY: kernel pid/groups zero is the rtnetlink destination.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != request.len() {
        return Err(invalid());
    }
    let mut messages = Vec::new();
    let mut total = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Linux route query timed out",
            ));
        }
        let mut buffer = [0u8; 65536];
        let mut size = std::mem::size_of_val(&address) as libc::socklen_t;
        // SAFETY: buffers are writable for the lengths passed; MSG_TRUNC detects oversized datagrams.
        let received = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&raw mut address).cast(),
                &mut size,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0
            || received as usize > buffer.len()
            || address.nl_pid != 0
            || address.nl_groups != 0
            || size as usize != std::mem::size_of_val(&address)
        {
            return Err(invalid());
        }
        total += received as usize;
        if total > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        let mut bytes = &buffer[..received as usize];
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                return Err(invalid());
            }
            let len = u32_at(&bytes[..4])? as usize;
            let aligned = (len + 3) & !3;
            if len < 16 || aligned > bytes.len() || u32_at(&bytes[8..12])? != 1 {
                return Err(invalid());
            }
            let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
            let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
            let payload = &bytes[16..len];
            if flags & 0x10 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Linux route dump changed",
                ));
            }
            match kind {
                2 => {
                    let code = i32::from_ne_bytes(
                        payload
                            .get(..4)
                            .ok_or_else(invalid)?
                            .try_into()
                            .map_err(|_| invalid())?,
                    );
                    if code < 0 && code != i32::MIN {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                    if code != 0 {
                        return Err(invalid());
                    }
                    return Ok(messages);
                }
                3 => {
                    if payload.len() >= 4 && u32_at(&payload[..4])? != 0 {
                        return Err(invalid());
                    }
                    return Ok(messages);
                }
                _ => messages.push(payload.to_vec()),
            }
            bytes = &bytes[aligned..];
        }
    }
}
fn dump(kind: u16, ipv6: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut header = [0; 12];
    header[0] = if ipv6 { 10 } else { 2 };
    exchange(kind, DUMP, &header)
}

pub(super) fn default_interface(ipv6: bool) -> io::Result<Option<String>> {
    let mut selected: Option<(u32, u32)> = None;
    for route in dump(GET_ROUTE, ipv6)? {
        if route.len() < 12 {
            return Err(invalid());
        }
        if route[1] != 0 || route[7] != 1 || property(&route[12..], 15, u32::from(route[4]))? != 254
        {
            continue;
        }
        let index = property(&route[12..], 4, 0)?;
        let metric = property(&route[12..], 6, 0)?;
        if index > 0 && selected.is_none_or(|(previous, _)| metric < previous) {
            selected = Some((metric, index));
        }
    }
    selected
        .map(|(_, index)| {
            let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
            // SAFETY: name has IF_NAMESIZE writable bytes; successful output is NUL terminated.
            if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { CStr::from_ptr(name.as_ptr()) }
                .to_string_lossy()
                .into_owned())
        })
        .transpose()
}
pub(super) fn ensure_available(ipv6: bool, table: u32, priority: u32) -> io::Result<()> {
    for route in dump(GET_ROUTE, ipv6)? {
        if route.len() < 12 {
            return Err(invalid());
        }
        if property(&route[12..], 15, u32::from(route[4]))? == table {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Linux TUN routing table is occupied",
            ));
        }
    }
    for rule in dump(GET_RULE, ipv6)? {
        if rule.len() < 12 {
            return Err(invalid());
        }
        let found_priority = property(&rule[12..], 6, 0)?;
        if (priority..=priority + super::plan::RULE_SPAN).contains(&found_priority) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Linux TUN rule priority is occupied",
            ));
        }
    }
    Ok(())
}
fn prefix_attribute(payload: &mut Vec<u8>, kind: u16, prefix: crate::config::IpCidr) {
    match prefix.network {
        std::net::IpAddr::V4(address) => attr(payload, kind, &address.octets()),
        std::net::IpAddr::V6(address) => attr(payload, kind, &address.octets()),
    }
}
fn port_attribute(payload: &mut Vec<u8>, kind: u16, range: crate::config::PortRange) {
    let mut value = [0; 4];
    value[..2].copy_from_slice(&range.start.to_ne_bytes());
    value[2..].copy_from_slice(&range.end.to_ne_bytes());
    attr(payload, kind, &value);
}
fn message(change: &Change, add: bool) -> io::Result<(u16, Vec<u8>)> {
    let mut payload = vec![0; 12];
    let kind = match change {
        Change::Route(route) => {
            payload[0] = if route.ipv6 { 10 } else { 2 };
            payload[1] = route.destination.prefix_len;
            payload[5] = 4;
            payload[7] = 1; // RTPROT_STATIC / RTN_UNICAST
            attr(&mut payload, 15, &route.table.to_ne_bytes());
            attr(&mut payload, 4, &route.index.to_ne_bytes());
            if route.destination.prefix_len != 0 {
                prefix_attribute(&mut payload, 1, route.destination);
            }
            if add { NEW_ROUTE } else { DEL_ROUTE }
        }
        Change::Rule(rule) => {
            payload[0] = if rule.ipv6 { 10 } else { 2 };
            payload[7] = match rule.action {
                Action::Goto(_) => 2,
                Action::Nop => 3,
                Action::Unreachable => 7,
                _ => 1,
            };
            match rule.action {
                Action::Table(table) => attr(&mut payload, 15, &table.to_ne_bytes()),
                Action::MainNonDefault => {
                    payload[4] = 254;
                    attr(&mut payload, 14, &0u32.to_ne_bytes());
                }
                Action::Goto(priority) => attr(&mut payload, 4, &priority.to_ne_bytes()),
                Action::Unreachable | Action::Nop => {}
            }
            if rule.selector != Selector::Any {
                attr(&mut payload, 3, b"lo\0"); // Local application traffic only.
                attr(&mut payload, 10, &0u32.to_ne_bytes());
                attr(&mut payload, 16, &u32::MAX.to_ne_bytes());
            }
            match rule.selector {
                Selector::Uid(range) => {
                    let mut bytes = [0; 8];
                    bytes[..4].copy_from_slice(&range.start.to_ne_bytes());
                    bytes[4..].copy_from_slice(&range.end.to_ne_bytes());
                    attr(&mut payload, 20, &bytes);
                }
                Selector::SourcePort(range) => port_attribute(&mut payload, 23, range),
                Selector::DestinationPort(range) => port_attribute(&mut payload, 24, range),
                Selector::Local | Selector::Any => {}
            }
            attr(&mut payload, 6, &rule.priority.to_ne_bytes());
            if add { NEW_RULE } else { DEL_RULE }
        }
        _ => return Err(invalid()),
    };
    Ok((kind, payload))
}
pub(super) fn change(change: &Change, add: bool) -> io::Result<()> {
    let (kind, payload) = message(change, add)?;
    exchange(kind, ACK | if add { CREATE_EXCL } else { 0 }, &payload).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_attributes_preserve_native_endian_and_padding() {
        let mut bytes = Vec::new();
        attr(&mut bytes, 15, &2022u32.to_ne_bytes());
        attr(&mut bytes, 3, b"lo\0");
        assert_eq!(property(&bytes, 15, 0).unwrap(), 2022);
        assert_eq!(attribute(&bytes, 3).unwrap(), Some(b"lo\0".as_slice()));
        for len in [1, 3, 7, 9] {
            assert!(attribute(&bytes[..len], 15).is_err());
        }
    }
    #[test]
    fn native_tun_wire_uses_exact_indices_cidrs_uid_and_native_port_attributes() {
        use super::super::plan::{Route, Rule};
        let route = Change::Route(Route {
            ipv6: false,
            index: 17,
            table: 2500,
            destination: crate::config::IpCidr {
                network: "203.0.113.0".parse().unwrap(),
                prefix_len: 24,
            },
        });
        let (kind, bytes) = message(&route, true).unwrap();
        assert_eq!(kind, NEW_ROUTE);
        assert_eq!(bytes[1], 24);
        assert_eq!(property(&bytes[12..], 15, 0).unwrap(), 2500);
        assert_eq!(
            attribute(&bytes[12..], 1).unwrap(),
            Some(&[203, 0, 113, 0][..])
        );
        assert_eq!(message(&route, false).unwrap().1, bytes);
        for selector in [
            Selector::Uid(crate::config::UidRange {
                start: 1001,
                end: 1003,
            }),
            Selector::SourcePort(crate::config::PortRange {
                start: 20000,
                end: 20003,
            }),
            Selector::DestinationPort(crate::config::PortRange {
                start: 443,
                end: 443,
            }),
        ] {
            let rule = Change::Rule(Rule {
                ipv6: true,
                priority: 8500,
                selector,
                action: Action::Goto(8504),
            });
            let (_, bytes) = message(&rule, true).unwrap();
            assert_eq!(bytes[7], 2);
            assert_eq!(property(&bytes[12..], 4, 0).unwrap(), 8504);
            assert_eq!(
                attribute(&bytes[12..], 3).unwrap(),
                Some(b"lo\0".as_slice())
            );
            assert_eq!(property(&bytes[12..], 16, 0).unwrap(), u32::MAX);
            match selector {
                Selector::Uid(range) => {
                    let data = attribute(&bytes[12..], 20).unwrap().unwrap();
                    assert_eq!(u32_at(&data[..4]).unwrap(), range.start);
                    assert_eq!(u32_at(&data[4..]).unwrap(), range.end);
                }
                Selector::SourcePort(range) | Selector::DestinationPort(range) => {
                    let kind = if matches!(selector, Selector::SourcePort(_)) {
                        23
                    } else {
                        24
                    };
                    let data = attribute(&bytes[12..], kind).unwrap().unwrap();
                    assert_eq!(
                        u16::from_ne_bytes(data[..2].try_into().unwrap()),
                        range.start
                    );
                    assert_eq!(u16::from_ne_bytes(data[2..].try_into().unwrap()), range.end);
                }
                _ => unreachable!(),
            }
            assert_eq!(message(&rule, false).unwrap().1, bytes);
        }
    }
}
