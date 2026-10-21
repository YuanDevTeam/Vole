//! Opt-in Linux MPTCP at the same protected socket-creation seam as TCP.
use super::Dialer;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use tokio::net::TcpSocket;

impl Dialer {
    pub(super) fn permits_mptcp(&self) -> bool {
        if !self.mptcp
            || self.protector.is_some()
            || self.source_binding.is_some()
            || self.egress.interface.is_some()
            || self.dns_binding.is_some()
        {
            return false;
        }
        #[cfg(feature = "tun")]
        if self
            .linux_policy
            .as_ref()
            .is_some_and(|policy| !policy.permits_mptcp())
        {
            return false;
        }
        true
    }
}

pub(super) fn socket(ipv6: bool) -> io::Result<TcpSocket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::MPTCP)) {
        Ok(socket) => socket,
        Err(error) if unavailable(&error) => {
            // Only creation-time capability errors permit TCP fallback. Policy
            // and protect run afterwards on the returned socket and fail closed.
            Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?
        }
        Err(error) => return Err(error),
    };
    socket.set_nonblocking(true)?;
    Ok(TcpSocket::from_std_stream(socket.into()))
}

fn unavailable(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::EgressOptions, dialer::SocketProtector};
    use std::sync::Arc;

    struct Protector;
    impl SocketProtector for Protector {
        fn protect(&self, _: i32) -> io::Result<()> {
            panic!("offline policy test must not initialize a socket")
        }
    }

    #[test]
    fn kernel_subflows_require_host_owned_paths_without_fd_only_constraints() {
        assert!(!Dialer::default().permits_mptcp());
        let dialer = Dialer::default().with_mptcp(true);
        assert!(dialer.permits_mptcp());
        assert!(
            dialer
                .clone()
                .with_egress(&EgressOptions {
                    routing_mark: 42,
                    ..Default::default()
                })
                .permits_mptcp()
        );
        assert!(
            !dialer
                .clone()
                .with_egress(&EgressOptions {
                    interface: Some("eth0".into()),
                    ..Default::default()
                })
                .permits_mptcp()
        );
        assert!(
            !dialer
                .clone()
                .with_source_ip("192.0.2.1".parse().unwrap())
                .permits_mptcp()
        );
        assert!(!dialer.with_protector(Arc::new(Protector)).permits_mptcp());
    }

    #[test]
    fn capability_fallback_does_not_hide_policy_or_resource_errors() {
        for errno in [libc::EINVAL, libc::EPROTONOSUPPORT, libc::ENOPROTOOPT] {
            assert!(unavailable(&io::Error::from_raw_os_error(errno)));
        }
        for errno in [libc::EPERM, libc::EACCES, libc::EMFILE, libc::ENOMEM] {
            assert!(!unavailable(&io::Error::from_raw_os_error(errno)));
        }
    }
}
