//! Public libproc socket-fd API, using the SDK sys/proc_info.h ABI.
//! No private version-dependent pcblist offsets or elevated privileges.
use super::*;
use std::{
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[repr(C)]
#[derive(Clone, Copy)]
struct FileInfo {
    flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct SockBuf {
    bytes: u32,
    high: u32,
    count: u32,
    maximum: u32,
    low: u32,
    flags: i16,
    timeout: i16,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Inet6 {
    hop: u8,
    checksum: i32,
    index: u16,
    hops: i16,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct InetInfo {
    foreign_port: i32,
    local_port: i32,
    generation: u64,
    flags: u32,
    flow: u32,
    version: u8,
    ttl: u8,
    reserved: u32,
    foreign: [u8; 16],
    local: [u8; 16],
    tos: u8,
    ipv6: Inet6,
}
#[repr(C)]
#[derive(Clone, Copy)]
union Protocol {
    inet: InetInfo,
    opaque: [u64; 66],
}
#[repr(C)]
struct SocketInfo {
    stat: libc::vinfo_stat,
    socket: u64,
    pcb: u64,
    kind: i32,
    protocol: i32,
    family: i32,
    options: [i16; 8],
    oob: u32,
    receive: SockBuf,
    send: SockBuf,
    info_kind: i32,
    reserved: u32,
    info: Protocol,
}
#[repr(C)]
struct SocketFd {
    file: FileInfo,
    socket: SocketInfo,
}

fn socket(pid: i32, fd: i32) -> Option<SocketFd> {
    let mut value: SocketFd = unsafe { zeroed() };
    let bytes = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            3,
            (&mut value as *mut SocketFd).cast(),
            size_of::<SocketFd>() as i32,
        )
    };
    (bytes as usize == size_of::<SocketFd>()).then_some(value)
}
fn matches(value: &SocketFd, query: Query) -> bool {
    let protocol = match query.network {
        Network::Tcp => libc::IPPROTO_TCP,
        Network::Udp => libc::IPPROTO_UDP,
    };
    if value.socket.protocol != protocol
        || value.socket.family
            != if query.source.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            }
        || !matches!(value.socket.info_kind, 1 | 2)
    {
        return false;
    }
    let inet = unsafe { value.socket.info.inet };
    let ip = |bytes: [u8; 16]| {
        if query.source.is_ipv4() {
            IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
        } else {
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
    };
    query.source == SocketAddr::new(ip(inet.local), u16::from_be(inet.local_port as u16))
        && query.destination
            == SocketAddr::new(ip(inet.foreign), u16::from_be(inet.foreign_port as u16))
}
pub(super) fn platform(query: Query, budget: &mut Budget<'_>) -> io::Result<Identity> {
    let mut pids = vec![0i32; MAX_ENTRIES];
    let bytes = unsafe {
        libc::proc_listpids(
            1, // PROC_ALL_PIDS, public sys/proc_info.h
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<i32>()) as i32,
        )
    };
    if bytes <= 0 || bytes as usize >= pids.len() * size_of::<i32>() {
        return Ok(Default::default());
    }
    let mut identity = None;
    let mut owner = None;
    for pid in pids
        .into_iter()
        .take(bytes as usize / size_of::<i32>())
        .filter(|pid| *pid > 0)
    {
        budget.visit()?;
        let mut fds = vec![unsafe { zeroed::<libc::proc_fdinfo>() }; 1024];
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                (fds.len() * size_of::<libc::proc_fdinfo>()) as i32,
            )
        };
        if bytes <= 0 || bytes as usize >= fds.len() * size_of::<libc::proc_fdinfo>() {
            continue;
        }
        for fd in fds
            .into_iter()
            .take(bytes as usize / size_of::<libc::proc_fdinfo>())
            .filter(|fd| fd.proc_fdtype == 2)
        {
            budget.visit()?;
            let Some(before) = socket(pid, fd.proc_fd) else {
                continue;
            };
            if !matches(&before, query) {
                continue;
            }
            let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let bytes =
                unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
            if bytes <= 0 || bytes as usize >= path.len() {
                continue;
            }
            budget.check()?;
            let Some(after) = socket(pid, fd.proc_fd) else {
                continue;
            };
            if !matches(&after, query)
                || before.socket.socket != after.socket.socket
                || before.socket.pcb != after.socket.pcb
                || unsafe { before.socket.info.inet.generation }
                    != unsafe { after.socket.info.inet.generation }
            {
                continue;
            }
            path.truncate(bytes as usize);
            if path.last() == Some(&0) {
                path.pop();
            }
            let Some(found) = String::from_utf8(path).ok().and_then(Identity::from_path) else {
                continue;
            };
            if owner.is_some_and(|owner| owner != pid) {
                return Ok(Default::default());
            }
            owner = Some(pid);
            identity = Some(found);
        }
    }
    Ok(identity.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_libproc_layout_and_exact_tuple_are_checked() {
        // macOS public 64-bit SDK ABI, not private kernel PCB layout.
        assert_eq!(size_of::<InetInfo>(), 80);
        assert_eq!(size_of::<SocketFd>(), 792);
        let mut value: SocketFd = unsafe { zeroed() };
        value.socket.protocol = libc::IPPROTO_TCP;
        value.socket.family = libc::AF_INET;
        value.socket.info_kind = 2;
        let mut inet: InetInfo = unsafe { zeroed() };
        inet.local[12..].copy_from_slice(&[127, 0, 0, 1]);
        inet.foreign[12..].copy_from_slice(&[192, 0, 2, 3]);
        inet.local_port = u16::to_be(1234) as i32;
        inet.foreign_port = u16::to_be(443) as i32;
        value.socket.info.inet = inet;
        let query = Query {
            network: Network::Tcp,
            source: "127.0.0.1:1234".parse().unwrap(),
            destination: "192.0.2.3:443".parse().unwrap(),
        };
        assert!(matches(&value, query));
        assert!(!matches(
            &value,
            Query {
                destination: "192.0.2.4:443".parse().unwrap(),
                ..query
            }
        ));
    }
}
