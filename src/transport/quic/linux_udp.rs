//! Linux ancillary messages on an existing protected UDP fd; no socket factory.
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use std::{
    io::{self, IoSliceMut},
    mem,
    os::fd::AsRawFd,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::net::UdpSocket;

const MAX_SEGMENTS: usize = 8;
const UDP_SEGMENT: libc::c_int = 103;
const UDP_GRO: libc::c_int = 104;

pub(super) struct SocketState {
    gso: AtomicBool,
}
impl SocketState {
    pub(super) fn new(
        io: &UdpSocket,
        settings: crate::config::QuicSocketSettings,
    ) -> io::Result<Option<Self>> {
        // Do not rely on reporting GRO=1 while aggregation remains enabled.
        match set_option(io, libc::SOL_UDP, UDP_GRO, 0) {
            Ok(()) => {
                if get_option(io, libc::SOL_UDP, UDP_GRO)? != 0 {
                    return Err(io::ErrorKind::Unsupported.into());
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => {}
            Err(error) => return Err(error),
        }
        if io.local_addr()?.is_ipv4() {
            set_option(
                io,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;
            if !settings.disable_ecn
                && set_option(io, libc::IPPROTO_IP, libc::IP_RECVTOS, 1).is_err()
            {
                return Ok(None);
            }
        } else {
            set_option(
                io,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;
            set_option(io, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)?;
            if !settings.disable_ecn
                && set_option(io, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1).is_err()
            {
                return Ok(None);
            }
        }
        Ok(Some(Self {
            gso: AtomicBool::new(!settings.disable_gso),
        }))
    }
    pub(super) fn may_fragment(&self) -> bool {
        false
    }
    pub(super) fn max_gso_segments(&self) -> usize {
        if self.gso.load(Ordering::Relaxed) {
            MAX_SEGMENTS
        } else {
            1
        }
    }
    pub(super) fn try_send(&self, io: &UdpSocket, transmit: &Transmit<'_>) -> io::Result<()> {
        // Old batches were generated while GSO was enabled. If an earlier
        // batch disabled it, discard these rather than partially replaying them.
        if transmit.segment_size.is_some() && !self.gso.load(Ordering::Relaxed) {
            return Ok(());
        }
        let destination = socket2::SockAddr::from(transmit.destination);
        let mut control = Control::default();
        let mut length = 0;
        if let Some(ecn) = transmit.ecn {
            let (level, kind) = if transmit.destination.is_ipv4() {
                (libc::IPPROTO_IP, libc::IP_TOS)
            } else {
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
            };
            control.push(&mut length, level, kind, &(ecn as libc::c_int))?;
        }
        if let Some(segment) = transmit.segment_size {
            let segment = u16::try_from(segment).map_err(|_| io::ErrorKind::InvalidInput)?;
            control.push(&mut length, libc::SOL_UDP, UDP_SEGMENT, &segment)?;
        }
        let mut iov = libc::iovec {
            iov_base: transmit.contents.as_ptr().cast_mut().cast(),
            iov_len: transmit.contents.len(),
        };
        let mut header: libc::msghdr = unsafe { mem::zeroed() };
        header.msg_name = destination.as_ptr().cast_mut().cast();
        header.msg_namelen = destination.len();
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        if length > 0 {
            header.msg_control = control.0.as_mut_ptr().cast();
            header.msg_controllen = length;
        }
        let sent = unsafe {
            libc::sendmsg(
                io.as_raw_fd(),
                &header,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent >= 0 {
            return if sent as usize == transmit.contents.len() {
                Ok(())
            } else {
                Err(io::ErrorKind::WriteZero.into())
            };
        }
        let error = io::Error::last_os_error();
        if disables_gso(transmit, error.raw_os_error()) {
            self.gso.store(false, Ordering::Relaxed);
        }
        Err(error)
    }
    pub(super) fn recv(
        &self,
        io: &UdpSocket,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let (Some(buffer), Some(meta)) = (buffers.first_mut(), metadata.first_mut()) else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let mut source = socket2::SockAddrStorage::zeroed();
        let mut control = Control::default();
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut header: libc::msghdr = unsafe { mem::zeroed() };
        header.msg_name =
            unsafe { source.view_as::<libc::sockaddr_storage>() as *mut libc::sockaddr_storage }
                .cast();
        header.msg_namelen = source.size_of();
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.0.as_mut_ptr().cast();
        header.msg_controllen = mem::size_of_val(&control);
        let received = unsafe { libc::recvmsg(io.as_raw_fd(), &mut header, libc::MSG_DONTWAIT) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let minimum =
            match unsafe { source.view_as::<libc::sockaddr_storage>() }.ss_family as libc::c_int {
                libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
                libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
                _ => return Err(io::ErrorKind::InvalidData.into()),
            };
        if (header.msg_namelen as usize) < minimum
            || (header.msg_namelen as usize) > mem::size_of_val(&source)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let address = unsafe { socket2::SockAddr::new(source, header.msg_namelen) }
            .as_socket()
            .ok_or(io::ErrorKind::InvalidData)?;
        let length = if header.msg_flags & libc::MSG_TRUNC != 0 {
            buffer.len().saturating_add(1)
        } else {
            received as usize
        };
        *meta = RecvMeta {
            addr: address,
            len: length,
            stride: length,
            ecn: if header.msg_flags & libc::MSG_CTRUNC == 0 {
                control.ecn(header.msg_controllen)?
            } else {
                None
            },
            dst_ip: None,
        };
        Ok(1)
    }
}
fn disables_gso(transmit: &Transmit<'_>, error: Option<i32>) -> bool {
    transmit.segment_size.is_some()
        && transmit.ecn.is_none()
        && matches!(error, Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP))
}
fn set_option(io: &UdpSocket, level: i32, name: i32, value: libc::c_int) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            io.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn get_option(io: &UdpSocket, level: i32, name: i32) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            io.as_raw_fd(),
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == 0 && length as usize == mem::size_of_val(&value) {
        Ok(value)
    } else if result != 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

// u64 supplies cmsghdr alignment. The two possible send messages fit within 48B;
// receive contains only IP_TOS/IPV6_TCLASS, never an unbounded metadata vector.
#[derive(Default)]
struct Control([u64; 8]);
impl Control {
    fn push<T: Copy>(
        &mut self,
        used: &mut usize,
        level: i32,
        kind: i32,
        value: &T,
    ) -> io::Result<()> {
        let space = unsafe { libc::CMSG_SPACE(mem::size_of::<T>() as _) } as usize;
        if *used > mem::size_of_val(self) || space > mem::size_of_val(self) - *used {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        unsafe {
            let header = self
                .0
                .as_mut_ptr()
                .cast::<u8>()
                .add(*used)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<T>() as _) as usize;
            ptr::write_unaligned(libc::CMSG_DATA(header).cast::<T>(), *value);
        }
        *used += space;
        Ok(())
    }
    fn ecn(&self, used: usize) -> io::Result<Option<EcnCodepoint>> {
        if used > mem::size_of_val(self) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let base = self.0.as_ptr().cast::<u8>();
        let mut offset = 0;
        let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
        while used.saturating_sub(offset) >= mem::size_of::<libc::cmsghdr>() {
            let header = unsafe { &*base.add(offset).cast::<libc::cmsghdr>() };
            if header.cmsg_len < minimum || header.cmsg_len > used - offset {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let data = unsafe { base.add(offset + minimum) };
            if header.cmsg_level == libc::IPPROTO_IP
                && header.cmsg_type == libc::IP_TOS
                && header.cmsg_len > minimum
            {
                return Ok(EcnCodepoint::from_bits(unsafe { *data }));
            }
            if header.cmsg_level == libc::IPPROTO_IPV6
                && header.cmsg_type == libc::IPV6_TCLASS
                && header.cmsg_len >= minimum + mem::size_of::<libc::c_int>()
            {
                return Ok(EcnCodepoint::from_bits(unsafe {
                    ptr::read_unaligned(data.cast::<libc::c_int>())
                } as u8));
            }
            let space = unsafe { libc::CMSG_SPACE((header.cmsg_len - minimum) as _) } as usize;
            if space == 0 || space > used - offset {
                break;
            }
            offset += space;
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_quic_memory_linux_control_is_fixed_aligned_and_decodes_actual_ecn() {
        let mut control = Control::default();
        let mut used = 0;
        control
            .push(&mut used, libc::SOL_UDP, UDP_SEGMENT, &1200_u16)
            .unwrap();
        control
            .push(&mut used, libc::IPPROTO_IP, libc::IP_TOS, &2_u8)
            .unwrap();
        assert!(used <= 48);
        assert_eq!(control.ecn(used).unwrap(), Some(EcnCodepoint::Ect0));
        let mut control = Control::default();
        let mut used = 0;
        control
            .push(&mut used, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &3_i32)
            .unwrap();
        assert_eq!(control.ecn(used).unwrap(), Some(EcnCodepoint::Ce));
        assert!(control.ecn(mem::size_of_val(&control) + 1).is_err());
        assert!(control.push(&mut used, 0, 0, &[0_u8; 64]).is_err());
    }
    #[test]
    fn physical_quic_memory_gso_disables_only_for_capability_errors_not_would_block() {
        let mut transmit = Transmit {
            destination: "192.0.2.1:443".parse().unwrap(),
            contents: &[1; 2400],
            ecn: None,
            segment_size: Some(1200),
            src_ip: None,
        };
        for value in [libc::ENOPROTOOPT, libc::EOPNOTSUPP] {
            assert!(disables_gso(&transmit, Some(value)));
        }
        transmit.ecn = Some(EcnCodepoint::Ect0);
        assert!(!disables_gso(&transmit, Some(libc::ENOPROTOOPT)));
        transmit.ecn = None;
        transmit.segment_size = None;
        assert!(!disables_gso(&transmit, Some(libc::ENOPROTOOPT)));
        transmit.segment_size = Some(1200);
        for value in [
            libc::EAGAIN,
            libc::EINTR,
            libc::EPERM,
            libc::EMSGSIZE,
            libc::EINVAL,
            libc::EIO,
        ] {
            assert!(!disables_gso(&transmit, Some(value)));
        }
    }
}
