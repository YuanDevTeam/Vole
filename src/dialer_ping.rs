//! Linux ping sockets only. Creation, protection and binding stay in Dialer.
use super::Dialer;
use crate::{
    config::IpCidr,
    platform::TunIo,
    resources::observation::{Guard, ResourceKind, track},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

pub(crate) struct PhysicalPing {
    socket: AsyncFd<Socket>,
    _guard: Guard,
    pub(crate) identifier: u16,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct PingReceipt {
    pub(crate) length: usize,
    pub(crate) peer: IpAddr,
    pub(crate) local: IpAddr,
    pub(crate) interface: u32,
}
impl Dialer {
    pub(crate) fn permit_ping_destination(&self, destination: IpAddr) -> io::Result<()> {
        self.require_permitted(SocketAddr::new(destination, 0))?;
        self.validate_egress()
    }
    // Reuse the same tracked initialization scope as TCP/UDP, including protect
    // callback cancellation and shutdown's spawn_blocking owner barrier.
    pub(crate) async fn ping_tun_prefixes(&self, tun: Arc<TunIo>) -> io::Result<Vec<IpCidr>> {
        self.initialization
            .run(move |check| {
                check()?;
                let prefixes = tun.echo_prefixes()?;
                check()?;
                Ok(prefixes)
            })
            .await
    }
    pub(crate) async fn bind_ping_for(
        &self,
        destination: IpAddr,
        identifier: u16,
    ) -> io::Result<PhysicalPing> {
        self.permit_ping_destination(destination)?;
        if identifier == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let endpoint = SocketAddr::new(destination, 0);
        let mut bind = self
            .source_address_for(endpoint)?
            .unwrap_or_else(|| super::wildcard_address(destination.is_ipv6()));
        // Linux ping sockets use sin_port as the kernel-visible ICMP identifier.
        bind.set_port(identifier);
        let dialer = self.clone();
        let (socket, guard) = self
            .initialization
            .run(move |check| {
                let socket = Socket::new(
                    if destination.is_ipv6() {
                        Domain::IPV6
                    } else {
                        Domain::IPV4
                    },
                    Type::DGRAM,
                    Some(if destination.is_ipv6() {
                        Protocol::ICMPV6
                    } else {
                        Protocol::ICMPV4
                    }),
                )?;
                let guard = track(ResourceKind::Socket);
                check()?;
                if destination.is_ipv6() {
                    socket.set_only_v6(true)?;
                }
                socket.set_nonblocking(true)?;
                dialer.protect_socket(&socket)?;
                dialer.apply_socket_policy(&socket, endpoint)?;
                enable_packet_info(socket.as_raw_fd(), destination.is_ipv6())?;
                socket.bind(&bind.into())?;
                if socket.local_addr()?.as_socket().map(|a| a.port()) != Some(identifier) {
                    return Err(io::Error::other(
                        "ping socket did not retain its reserved identifier",
                    ));
                }
                check()?;
                Ok((socket, guard))
            })
            .await?;
        Ok(PhysicalPing {
            socket: AsyncFd::new(socket)?,
            _guard: guard,
            identifier,
        })
    }
}
fn enable_packet_info(fd: libc::c_int, ipv6: bool) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    // SAFETY: fd is live; enabled has the Linux integer socket-option layout.
    if unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&raw const enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
impl PhysicalPing {
    pub(crate) async fn send(&self, destination: IpAddr, bytes: &[u8]) -> io::Result<()> {
        let address = SocketAddr::new(destination, 0).into();
        loop {
            let mut ready = self.socket.writable().await?;
            match ready.try_io(|socket| socket.get_ref().send_to(bytes, &address)) {
                Ok(Ok(n)) if n == bytes.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::Error::other("partial ICMP datagram write")),
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
        }
    }
    pub(crate) async fn recv(&self, bytes: &mut [u8]) -> io::Result<PingReceipt> {
        loop {
            let mut ready = self.socket.readable().await?;
            match ready.try_io(|socket| receive(socket.get_ref().as_raw_fd(), bytes)) {
                Ok(result) => return result,
                Err(_) => {}
            }
        }
    }
}
// cmsghdr requires native alignment. This buffer is larger than either pktinfo
// message, without a per-receive heap allocation or a 64-KiB scratch buffer.
#[repr(C, align(16))]
struct Control([u8; 128]);
fn receive(fd: libc::c_int, bytes: &mut [u8]) -> io::Result<PingReceipt> {
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control = Control([0; 128]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut peer).cast();
    msg.msg_namelen = std::mem::size_of_val(&peer) as libc::socklen_t;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len();
    // SAFETY: all output buffers have the capacities advertised in msghdr.
    let length = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_TRUNC) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize > bytes.len()
        || msg.msg_controllen > control.0.len()
        || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ICMP datagram",
        ));
    }
    let peer = match i32::from(peer.ss_family) {
        libc::AF_INET if msg.msg_namelen as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let address =
                unsafe { std::ptr::read_unaligned((&raw const peer).cast::<libc::sockaddr_in>()) };
            IpAddr::V4(address.sin_addr.s_addr.to_ne_bytes().into())
        }
        libc::AF_INET6 if msg.msg_namelen as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let address =
                unsafe { std::ptr::read_unaligned((&raw const peer).cast::<libc::sockaddr_in6>()) };
            IpAddr::V6(address.sin6_addr.s6_addr.into())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ICMP peer address is incomplete",
            ));
        }
    };
    let mut pktinfo = None;
    // SAFETY: msg_control is aligned and refers to the kernel's checked length.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        let base = cmsg as usize - msg.msg_control as usize;
        if header.cmsg_len < minimum
            || base
                .checked_add(header.cmsg_len)
                .is_none_or(|end| end > msg.msg_controllen)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ICMP ancillary header",
            ));
        }
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        let found = if header.cmsg_level == libc::IPPROTO_IP
            && header.cmsg_type == libc::IP_PKTINFO
            && header.cmsg_len
                == unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as _) as usize }
        {
            let info = unsafe { std::ptr::read_unaligned(data.cast::<libc::in_pktinfo>()) };
            Some((
                IpAddr::V4(info.ipi_addr.s_addr.to_ne_bytes().into()),
                info.ipi_ifindex as u32,
            ))
        } else if header.cmsg_level == libc::IPPROTO_IPV6
            && header.cmsg_type == libc::IPV6_PKTINFO
            && header.cmsg_len
                == unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as _) as usize }
        {
            let info = unsafe { std::ptr::read_unaligned(data.cast::<libc::in6_pktinfo>()) };
            Some((IpAddr::V6(info.ipi6_addr.s6_addr.into()), info.ipi6_ifindex))
        } else {
            None
        };
        if let Some(found) = found {
            if pktinfo.replace(found).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ambiguous ICMP packet info",
                ));
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    let (local, interface) = pktinfo
        .filter(|(ip, index)| ip.is_ipv4() == peer.is_ipv4() && *index != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ICMP packet info is missing"))?;
    if local.is_unspecified() || local.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP packet info is not unicast",
        ));
    }
    Ok(PingReceipt {
        length: length as usize,
        peer,
        local,
        interface,
    })
}
