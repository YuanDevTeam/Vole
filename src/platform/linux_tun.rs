//! Read-only validation of a borrowed Linux kernel TUN, including cross-netns
//! descriptors. No interface, route, file-status flag or caller namespace is
//! changed here.

use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    thread,
};

#[cfg(feature = "interop-test")]
#[path = "linux_tun_echo.rs"]
mod echo;
#[cfg(feature = "interop-test")]
pub(super) use echo::interface_prefixes;

const NETLINK_HEADER: usize = 16;
const LINK_HEADER: usize = 16;
const MAX_LINK_MESSAGE: usize = 8192;
const QUERY_SEQUENCE: u32 = 1;
// Linux UAPI linux/if_link.h, tun section (not exposed by libc).
const IFLA_TUN_TYPE: u16 = 3;
const IFLA_TUN_PI: u16 = 4;
const IFLA_TUN_VNET_HDR: u16 = 5;
const IFLA_TUN_MULTI_QUEUE: u16 = 7;

pub(super) fn validate(fd: BorrowedFd<'_>, mtu: u16) -> io::Result<()> {
    // SAFETY: all-zero ifreq is valid storage for the kernel's output.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: fd is borrowed and request is writable for a complete ifreq.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
        return Err(os_error("Linux TUNGETIFF"));
    }
    // SAFETY: successful TUNGETIFF initializes the flags union member.
    validate_flags(unsafe { request.ifr_ifru.ifru_flags } as u16)?;
    if request.ifr_name[0] == 0 || !request.ifr_name.contains(&0) {
        return Err(invalid("Linux TUN returned an invalid interface name"));
    }

    // TUNGETIFF aliases IFF_NOFILTER with IFF_NO_PI and therefore cannot alone
    // prove raw-IP framing. Query the actual tun attributes via rtnetlink in
    // the device's namespace, not the physical-egress namespace of the core.
    // SAFETY: this ioctl returns a newly owned namespace fd, not a pointer.
    let namespace_fd = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETDEVNETNS) };
    if namespace_fd < 0 {
        return Err(os_error("Linux TUNGETDEVNETNS"));
    }
    // SAFETY: a successful TUNGETDEVNETNS returns a fresh owned descriptor.
    let namespace = File::from(unsafe { OwnedFd::from_raw_fd(namespace_fd) });
    let current_namespace = File::open("/proc/thread-self/ns/net")?;
    let target_identity = namespace.metadata()?;
    let current_identity = current_namespace.metadata()?;
    let name = request.ifr_name;
    if target_identity.dev() == current_identity.dev()
        && target_identity.ino() == current_identity.ino()
    {
        return validate_link(name, mtu);
    }

    // setns is thread-local. Only this short-lived thread enters the device
    // namespace; Invoke, Tokio and outbound workers retain physical egress.
    // Joining completes validation (and closes its fds) before startup proceeds.
    thread::Builder::new()
        .name("vole-tun-validate".into())
        .spawn(move || {
            // SAFETY: namespace remains open; CLONE_NEWNET changes only this
            // disposable thread. No caller-owned socket is moved into it.
            if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
                return Err(os_error("Linux TUN namespace entry"));
            }
            validate_link(name, mtu)
        })?
        .join()
        .map_err(|_| io::Error::other("Linux TUN validation thread panicked"))?
}

fn validate_flags(flags: u16) -> io::Result<()> {
    if flags != (libc::IFF_TUN | libc::IFF_NO_PI) as u16 {
        return Err(invalid(
            "Linux TUN requires IFF_TUN | IFF_NO_PI without additional modes",
        ));
    }
    Ok(())
}

fn validate_link(name: [libc::c_char; libc::IFNAMSIZ], mtu: u16) -> io::Result<()> {
    let control = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    // SAFETY: all-zero ifreq is valid before writing its interface name.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name = name;
    // SAFETY: control is open in the owning netns and request is writable.
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFINDEX, &mut request) } < 0 {
        return Err(os_error("Linux TUN interface index query"));
    }
    // SAFETY: successful SIOCGIFINDEX initializes the index union member.
    let index = unsafe { request.ifr_ifru.ifru_ifindex };
    if index <= 0 {
        return Err(invalid("Linux TUN returned an invalid interface index"));
    }

    let netlink = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: timeout is readable for the supplied size and netlink is open.
        if unsafe {
            libc::setsockopt(
                netlink.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast(),
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } < 0
        {
            return Err(os_error("Linux TUN link query deadline"));
        }
    }
    let mut query = [0_u8; NETLINK_HEADER + LINK_HEADER];
    let query_len = query.len() as u32;
    query[0..4].copy_from_slice(&query_len.to_ne_bytes());
    query[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    query[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    query[8..12].copy_from_slice(&QUERY_SEQUENCE.to_ne_bytes());
    query[NETLINK_HEADER + 4..NETLINK_HEADER + 8].copy_from_slice(&index.to_ne_bytes());
    // SAFETY: zeroed sockaddr_nl has kernel destination pid/groups zero.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: query and address are readable for their declared lengths.
    let sent = unsafe {
        libc::sendto(
            netlink.as_raw_fd(),
            query.as_ptr().cast(),
            query.len(),
            0,
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(os_error("Linux TUN link query"));
    }
    if sent as usize != query.len() {
        return Err(invalid("Linux TUN link query was incomplete"));
    }
    let mut response = [0_u8; MAX_LINK_MESSAGE];
    let mut address_len = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: response/address are writable for their declared capacities.
    // MSG_TRUNC reports the full datagram length so oversized data fails closed.
    let received = unsafe {
        libc::recvfrom(
            netlink.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            libc::MSG_TRUNC,
            (&raw mut address).cast(),
            &mut address_len,
        )
    };
    if received < 0 {
        return Err(os_error("Linux TUN link query response"));
    }
    if received as usize > response.len()
        || address_len as usize != std::mem::size_of_val(&address)
        || address.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || address.nl_pid != 0
        || address.nl_groups != 0
    {
        return Err(invalid("Linux TUN link query returned an invalid response"));
    }
    validate_link_message(&response[..received as usize], index, mtu)
}

fn validate_link_message(message: &[u8], index: i32, expected_mtu: u16) -> io::Result<()> {
    if message.len() < NETLINK_HEADER
        || native_u32(&message[0..4])? as usize != message.len()
        || native_u32(&message[8..12])? != QUERY_SEQUENCE
    {
        return Err(invalid("Linux TUN link response header is invalid"));
    }
    let kind = native_u16(&message[4..6])?;
    if kind == libc::NLMSG_ERROR as u16 {
        let error = message
            .get(NETLINK_HEADER..NETLINK_HEADER + 4)
            .ok_or_else(|| invalid("Linux TUN link error response is incomplete"))?;
        let error = i32::from_ne_bytes(error.try_into().map_err(|_| invalid("invalid errno"))?);
        return Err(if error < 0 && error != i32::MIN {
            io::Error::from_raw_os_error(-error)
        } else {
            invalid("Linux TUN link query did not return device parameters")
        });
    }
    if kind != libc::RTM_NEWLINK
        || message.len() < NETLINK_HEADER + LINK_HEADER
        || native_u16(&message[6..8])? & libc::NLM_F_MULTI as u16 != 0
        || native_u32(&message[NETLINK_HEADER + 4..NETLINK_HEADER + 8])? != index as u32
    {
        return Err(invalid(
            "Linux TUN link response is not the requested device",
        ));
    }
    let attributes = &message[NETLINK_HEADER + LINK_HEADER..];
    let mtu = attribute(attributes, libc::IFLA_MTU)?
        .ok_or_else(|| invalid("Linux TUN link response is missing MTU"))?;
    if native_u32(mtu)? != u32::from(expected_mtu) {
        return Err(invalid("Linux TUN interface MTU does not match tun.mtu"));
    }
    let info = attribute(attributes, libc::IFLA_LINKINFO)?
        .ok_or_else(|| invalid("Linux TUN link response is missing device information"))?;
    if attribute(info, libc::IFLA_INFO_KIND)? != Some(&b"tun\0"[..]) {
        return Err(invalid("Linux TUN link response is not a TUN device"));
    }
    let data = attribute(info, libc::IFLA_INFO_DATA)?
        .ok_or_else(|| invalid("Linux TUN link response is missing TUN parameters"))?;
    for (kind, expected) in [
        (IFLA_TUN_TYPE, libc::IFF_TUN as u8),
        (IFLA_TUN_PI, 0),
        (IFLA_TUN_VNET_HDR, 0),
        (IFLA_TUN_MULTI_QUEUE, 0),
    ] {
        if attribute(data, kind)? != Some(&[expected][..]) {
            return Err(invalid(
                "Linux TUN requires raw-IP single-queue parameters without VNET headers",
            ));
        }
    }
    Ok(())
}

// Native-endian, four-byte-aligned UAPI attributes. Unknown attributes are
// skipped for kernel-version independence; malformed and duplicate matches
// fail closed. There is no recursive parsing or heap allocation.
fn attribute(mut bytes: &[u8], expected: u16) -> io::Result<Option<&[u8]>> {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid("Linux TUN link attribute is incomplete"));
        }
        let len = native_u16(&bytes[..2])? as usize;
        let kind = native_u16(&bytes[2..4])?;
        let aligned = (len + 3) & !3;
        if len < 4 || aligned > bytes.len() {
            return Err(invalid("Linux TUN link attribute length is invalid"));
        }
        if kind & 0x3fff == expected {
            if found.is_some() || kind & 0x4000 != 0 {
                return Err(invalid("Linux TUN link attribute is ambiguous"));
            }
            found = Some(&bytes[4..len]);
        }
        bytes = &bytes[aligned..];
    }
    Ok(found)
}

fn native_u16(bytes: &[u8]) -> io::Result<u16> {
    bytes
        .try_into()
        .map(u16::from_ne_bytes)
        .map_err(|_| invalid("Linux TUN link integer length is invalid"))
}

fn native_u32(bytes: &[u8]) -> io::Result<u32> {
    bytes
        .try_into()
        .map(u32::from_ne_bytes)
        .map_err(|_| invalid("Linux TUN link integer length is invalid"))
}

fn socket(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: socket returns a fresh descriptor or an error without ownership.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(os_error("Linux TUN metadata socket"));
    }
    // SAFETY: a successful socket call returns a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn os_error(operation: &'static str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{operation} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = 4 + value.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(len as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((len + 3) & !3, 0);
        bytes
    }

    fn link_message(mtu: u32, pi: u8, vnet: u8, multi: u8) -> Vec<u8> {
        let mut data = attr(IFLA_TUN_TYPE, &[libc::IFF_TUN as u8]);
        data.extend(attr(IFLA_TUN_PI, &[pi]));
        data.extend(attr(IFLA_TUN_VNET_HDR, &[vnet]));
        data.extend(attr(IFLA_TUN_MULTI_QUEUE, &[multi]));
        let mut info = attr(libc::IFLA_INFO_KIND, b"tun\0");
        info.extend(attr(libc::IFLA_INFO_DATA, &data));
        let mut message = vec![0; NETLINK_HEADER + LINK_HEADER];
        message[4..6].copy_from_slice(&libc::RTM_NEWLINK.to_ne_bytes());
        message[8..12].copy_from_slice(&QUERY_SEQUENCE.to_ne_bytes());
        message[NETLINK_HEADER + 4..NETLINK_HEADER + 8].copy_from_slice(&7_i32.to_ne_bytes());
        message.extend(attr(libc::IFLA_MTU, &mtu.to_ne_bytes()));
        message.extend(attr(libc::IFLA_LINKINFO, &info));
        let len = message.len() as u32;
        message[..4].copy_from_slice(&len.to_ne_bytes());
        message
    }

    #[test]
    fn raw_ip_single_queue_requires_exact_flags_and_kernel_parameters() {
        let required = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;
        assert!(validate_flags(required).is_ok());
        for flags in [
            libc::IFF_TUN,
            libc::IFF_TAP | libc::IFF_NO_PI,
            i32::from(required) | libc::IFF_VNET_HDR,
            i32::from(required) | libc::IFF_MULTI_QUEUE,
            i32::from(required) | libc::IFF_NAPI,
            i32::from(required) | libc::IFF_PERSIST,
        ] {
            assert!(validate_flags(flags as u16).is_err());
        }
        assert!(validate_link_message(&link_message(1500, 0, 0, 0), 7, 1500).is_ok());
        // TUNGETIFF can falsely expose NO_PI via the NOFILTER alias. The
        // authoritative IFLA_TUN_PI field must still reject this device.
        for parameters in [
            (1500, 1, 0, 0),
            (1500, 0, 1, 0),
            (1500, 0, 0, 1),
            (1400, 0, 0, 0),
        ] {
            let (mtu, pi, vnet, multi) = parameters;
            assert!(validate_link_message(&link_message(mtu, pi, vnet, multi), 7, 1500).is_err());
        }
    }

    #[test]
    fn link_metadata_matches_the_configured_mtu_without_reconfiguring() {
        for mtu in [1280, 1400, 1500, 9000, 65535] {
            let message = link_message(u32::from(mtu), 0, 0, 0);
            assert!(validate_link_message(&message, 7, mtu).is_ok());
            assert!(validate_link_message(&message, 7, mtu - 1).is_err());
        }
    }

    #[test]
    fn link_metadata_rejects_truncation_duplicates_and_wrong_identity() {
        let message = link_message(1500, 0, 0, 0);
        for end in 0..message.len() {
            assert!(validate_link_message(&message[..end], 7, 1500).is_err());
        }
        assert!(validate_link_message(&message, 8, 1500).is_err());
        let mut wrong_sequence = message.clone();
        wrong_sequence[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        assert!(validate_link_message(&wrong_sequence, 7, 1500).is_err());
        let mut malformed = message.clone();
        malformed.extend_from_slice(&[8, 0, 99, 0]);
        let len = malformed.len() as u32;
        malformed[..4].copy_from_slice(&len.to_ne_bytes());
        assert!(validate_link_message(&malformed, 7, 1500).is_err());
        let mut duplicate = message;
        duplicate.extend(attr(libc::IFLA_MTU, &1500_u32.to_ne_bytes()));
        let len = duplicate.len() as u32;
        duplicate[..4].copy_from_slice(&len.to_ne_bytes());
        assert!(validate_link_message(&duplicate, 7, 1500).is_err());
        assert!(attribute(&[3, 0, 4, 0], 4).is_err());
        assert!(attribute(&[8, 0, 4, 0], 4).is_err());
    }
}
