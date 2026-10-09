//! Shared client-proxy binding policy. All sockets are owned before serving.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
#[cfg(feature = "inbound-socks5")]
use tokio::net::UdpSocket;

use crate::config::ProxyAccess;

pub(crate) fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // Do not enable SO_REUSEPORT or Windows SO_REUSEADDR: an occupied port
    // must fail closed, not share or hijack a live listener.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

pub(crate) fn bind_proxy_tcp(port: u16, access: ProxyAccess) -> io::Result<Vec<TcpListener>> {
    if access.allow_lan
        && let Some(address) = access.bind_address
    {
        return Ok(vec![bind_tcp(SocketAddr::new(address, port))?]);
    }
    let ipv4 = if access.allow_lan {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    let first = bind_tcp(SocketAddr::new(IpAddr::V4(ipv4), port))?;
    let port = first.local_addr()?.port();
    let mut listeners = vec![first];
    if access.ipv6 {
        let ipv6 = if access.allow_lan {
            Ipv6Addr::UNSPECIFIED
        } else {
            Ipv6Addr::LOCALHOST
        };
        match bind_tcp(SocketAddr::new(IpAddr::V6(ipv6), port)) {
            Ok(listener) => listeners.push(listener),
            Err(error) if address_family_unavailable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(listeners)
}

#[cfg(feature = "inbound-socks5")]
pub(crate) fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // Darwin's default UDP send high-water mark is smaller than a legal SOCKS
    // reply. Configure this owned socket only; do not alter global sysctls.
    socket.set_send_buffer_size(crate::session::SOCKS5_UDP_PACKET_LIMIT + 1)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    UdpSocket::from_std(socket.into())
}

pub(crate) fn address_family_unavailable(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
        )
    }
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(10047 | 10043))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "inbound-socks5")]
    #[tokio::test]
    async fn socks_udp_send_buffer_covers_the_declared_wire_limit() {
        let socket = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(
            socket2::SockRef::from(&socket).send_buffer_size().unwrap()
                >= crate::session::SOCKS5_UDP_PACKET_LIMIT
        );
    }

    #[tokio::test]
    async fn policy_binds_loopback_or_wildcard_and_respects_ipv6() {
        for allow_lan in [false, true] {
            for ipv6 in [false, true] {
                let listeners = bind_proxy_tcp(
                    0,
                    ProxyAccess {
                        bind_address: None,
                        allow_lan,
                        ipv6,
                    },
                )
                .unwrap();
                let port = listeners[0].local_addr().unwrap().port();
                if !ipv6 {
                    assert_eq!(listeners.len(), 1);
                }
                for listener in &listeners {
                    let address = listener.local_addr().unwrap();
                    assert_eq!(address.port(), port);
                    assert_eq!(address.ip().is_loopback(), !allow_lan);
                    assert_eq!(address.ip().is_unspecified(), allow_lan);
                    if address.is_ipv6() {
                        assert!(ipv6);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn ipv6_bind_failure_releases_ipv4_and_only_missing_family_is_optional() {
        let occupied = match bind_tcp("[::1]:0".parse().unwrap()) {
            Ok(listener) => listener,
            Err(error) if address_family_unavailable(&error) => return,
            Err(error) => panic!("{error}"),
        };
        let port = occupied.local_addr().unwrap().port();
        let error = bind_proxy_tcp(
            port,
            ProxyAccess {
                bind_address: None,
                allow_lan: false,
                ipv6: true,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        drop(bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).unwrap());
        assert!(!address_family_unavailable(&io::Error::from(
            io::ErrorKind::AddrInUse
        )));
        assert!(!address_family_unavailable(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }
}
