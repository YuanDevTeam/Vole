//! Windows owner-PID tables and ordinary limited-information process handles.
use super::*;
use ::windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        NetworkManagement::IpHelper::*,
        System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
    core::PWSTR,
};
use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}
fn table(query: Query, budget: &Budget<'_>) -> io::Result<Vec<u8>> {
    let mut size = 0u32;
    let call = |buffer: Option<*mut std::ffi::c_void>, size: &mut u32| unsafe {
        let family = if query.source.is_ipv4() { 2 } else { 23 };
        match query.network {
            Network::Tcp => {
                GetExtendedTcpTable(buffer, size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
            }
            Network::Udp => {
                GetExtendedUdpTable(buffer, size, false, family, UDP_TABLE_OWNER_PID, 0)
            }
        }
    };
    call(None, &mut size);
    for _ in 0..2 {
        budget.check()?;
        if !(4..=MAX_TABLE as u32).contains(&size) {
            return Err(io::Error::other("process table exceeds budget"));
        }
        let mut bytes = vec![0u8; size as usize];
        let status = call(Some(bytes.as_mut_ptr().cast()), &mut size);
        if status == 0 && size as usize <= bytes.len() {
            bytes.truncate(size as usize);
            return Ok(bytes);
        }
        if status != 122 {
            break;
        } // ERROR_INSUFFICIENT_BUFFER, one bounded retry.
    }
    Err(io::Error::other("process owner table unavailable"))
}
fn ip4(value: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(value.to_ne_bytes()))
}
fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}
fn owner(query: Query, budget: &mut Budget<'_>) -> io::Result<Option<u32>> {
    let bytes = table(query, budget)?;
    let count = u32::from_ne_bytes(
        bytes
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| io::Error::other("invalid owner table"))?,
    ) as usize;
    let width = match (query.network, query.source.is_ipv6()) {
        (Network::Tcp, false) => size_of::<MIB_TCPROW_OWNER_PID>(),
        (Network::Tcp, true) => size_of::<MIB_TCP6ROW_OWNER_PID>(),
        (Network::Udp, false) => size_of::<MIB_UDPROW_OWNER_PID>(),
        (Network::Udp, true) => size_of::<MIB_UDP6ROW_OWNER_PID>(),
    };
    if count > MAX_ENTRIES
        || count
            .checked_mul(width)
            .and_then(|size| size.checked_add(4))
            .is_none_or(|size| size > bytes.len())
    {
        return Ok(None);
    }
    let mut found = None;
    for row in bytes[4..].chunks_exact(width).take(count) {
        budget.visit()?;
        // SDK row types contain only integers and byte arrays; unaligned reads
        // do not borrow the byte allocation at the C structure's alignment.
        let (local, remote, pid) = unsafe {
            match (query.network, query.source.is_ipv6()) {
                (Network::Tcp, false) => {
                    let row = row.as_ptr().cast::<MIB_TCPROW_OWNER_PID>().read_unaligned();
                    (
                        SocketAddr::new(ip4(row.dwLocalAddr), port(row.dwLocalPort)),
                        Some(SocketAddr::new(
                            ip4(row.dwRemoteAddr),
                            port(row.dwRemotePort),
                        )),
                        row.dwOwningPid,
                    )
                }
                (Network::Tcp, true) => {
                    let row = row
                        .as_ptr()
                        .cast::<MIB_TCP6ROW_OWNER_PID>()
                        .read_unaligned();
                    (
                        SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                            port(row.dwLocalPort),
                        ),
                        Some(SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                            port(row.dwRemotePort),
                        )),
                        row.dwOwningPid,
                    )
                }
                (Network::Udp, false) => {
                    let row = row.as_ptr().cast::<MIB_UDPROW_OWNER_PID>().read_unaligned();
                    (
                        SocketAddr::new(ip4(row.dwLocalAddr), port(row.dwLocalPort)),
                        None,
                        row.dwOwningPid,
                    )
                }
                (Network::Udp, true) => {
                    let row = row
                        .as_ptr()
                        .cast::<MIB_UDP6ROW_OWNER_PID>()
                        .read_unaligned();
                    (
                        SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                            port(row.dwLocalPort),
                        ),
                        None,
                        row.dwOwningPid,
                    )
                }
            }
        };
        // A wildcard/port-only row does not prove that a LAN source is local.
        if local != query.source
            || remote.is_some_and(|remote| remote != query.destination)
            || pid == 0
        {
            continue;
        }
        if found.is_some() {
            return Ok(None);
        }
        found = Some(pid);
    }
    Ok(found)
}
pub(super) fn platform(query: Query, budget: &mut Budget<'_>) -> io::Result<Identity> {
    let Some(pid) = owner(query, budget)? else {
        return Ok(Default::default());
    };
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return Ok(Default::default());
    };
    let handle = Process(handle);
    let mut path = vec![0u16; MAX_PATH / 2];
    let mut size = path.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut size,
        )
    }
    .is_err()
        || size as usize >= path.len()
    {
        return Ok(Default::default());
    }
    budget.check()?;
    if owner(query, budget)? != Some(pid) {
        return Ok(Default::default());
    }
    Ok(String::from_utf16(&path[..size as usize])
        .ok()
        .and_then(Identity::from_path)
        .unwrap_or_default())
}
