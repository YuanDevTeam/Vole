//! Gate-only Linux MPTCP API. No configuration field is accepted here.
use super::{Dialer, PhysicalStream, socket_initialization_cancelled};
use crate::resources::observation::ObservedIo;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
};
use tokio::{
    net::TcpSocket,
    time::{Instant, timeout_at},
};

const SOL_MPTCP: libc::c_int = 284;
const MPTCP_INFO: libc::c_int = 1;
const MPTCP_TCPINFO: libc::c_int = 2;
const TCP_INFO_PREFIX: usize = 8;
const MPTCP_SUBFLOW_ADDRS: libc::c_int = 3;
const HEADER: usize = 16;
const ADDRESS_BYTES: usize = 128;
const PATH_BYTES: usize = ADDRESS_BYTES * 2;
const MAX_PATHS: usize = 4;

impl Dialer {
    pub(super) async fn connect_mptcp_gate(
        &self,
        address: SocketAddr,
        deadline: Instant,
    ) -> io::Result<PhysicalStream> {
        let deadline = deadline.min(Instant::now() + self.connect_timeout);
        let operation = async {
            let (socket, guard, address) = self
                .prepare_tcp_socket_with(address, |ipv6| {
                    let socket = Socket::new(
                        if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
                        Type::STREAM,
                        Some(Protocol::MPTCP),
                    )?;
                    socket.set_nonblocking(true)?;
                    Ok(TcpSocket::from_std_stream(socket.into()))
                })
                .await?;
            let stream = socket.connect(address).await?;
            stream.set_nodelay(true)?;
            Ok(ObservedIo::with_guard(stream, guard))
        };
        tokio::select! {
            biased;
            () = self.initialization.cancellation.cancelled() => Err(socket_initialization_cancelled()),
            result = timeout_at(deadline, operation) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
        }
    }
}

/// Actual kernel-reported subflows, rather than a request bit or TCP fallback.
pub(super) fn paths(stream: &impl AsRawFd) -> io::Result<Vec<(SocketAddr, SocketAddr)>> {
    let mut info = [0_u8; 16];
    option(stream, MPTCP_INFO, &mut info)?;
    let flags = u32::from_ne_bytes(info[8..12].try_into().unwrap());
    if flags & 1 != 0 || flags & 2 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MPTCP peer negotiation fell back to TCP",
        ));
    }
    let before = all_paths(stream)?;
    let mut wire = [0_u8; HEADER + TCP_INFO_PREFIX * MAX_PATHS];
    wire[..4].copy_from_slice(&(HEADER as u32).to_ne_bytes());
    wire[12..16].copy_from_slice(&(TCP_INFO_PREFIX as u32).to_ne_bytes());
    let length = option(stream, MPTCP_TCPINFO, &mut wire)?;
    let states = decode_states(&wire[..length])?;
    // The two public options iterate the same FD's subflow list. A mutation
    // between reads is a transient sample, not two proven established paths.
    if before.len() != states.len() || before != all_paths(stream)? {
        return Ok(Vec::new());
    }
    Ok(before
        .into_iter()
        .zip(states)
        .filter_map(|(path, state)| (state == 1).then_some(path))
        .collect())
}

fn all_paths(stream: &impl AsRawFd) -> io::Result<Vec<(SocketAddr, SocketAddr)>> {
    let mut wire = [0_u8; HEADER + PATH_BYTES * MAX_PATHS];
    wire[..4].copy_from_slice(&(HEADER as u32).to_ne_bytes());
    wire[12..16].copy_from_slice(&(PATH_BYTES as u32).to_ne_bytes());
    let length = option(stream, MPTCP_SUBFLOW_ADDRS, &mut wire)?;
    decode_paths(&wire[..length])
}

fn decode_states(wire: &[u8]) -> io::Result<Vec<u8>> {
    if wire.len() < HEADER {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let count = u32::from_ne_bytes(wire[4..8].try_into().unwrap()) as usize;
    let kernel_size = u32::from_ne_bytes(wire[8..12].try_into().unwrap()) as usize;
    let user_size = u32::from_ne_bytes(wire[12..16].try_into().unwrap()) as usize;
    if count > MAX_PATHS
        || kernel_size < TCP_INFO_PREFIX
        || user_size != TCP_INFO_PREFIX
        || wire.len() < HEADER + count * TCP_INFO_PREFIX
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MPTCP TCP_INFO output exceeds the gate ABI budget",
        ));
    }
    Ok((0..count)
        .map(|index| wire[HEADER + index * TCP_INFO_PREFIX])
        .collect())
}

fn decode_paths(wire: &[u8]) -> io::Result<Vec<(SocketAddr, SocketAddr)>> {
    if wire.len() < HEADER {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let count = u32::from_ne_bytes(wire[4..8].try_into().unwrap()) as usize;
    let kernel_size = u32::from_ne_bytes(wire[8..12].try_into().unwrap()) as usize;
    let user_size = u32::from_ne_bytes(wire[12..16].try_into().unwrap()) as usize;
    if count > MAX_PATHS
        || kernel_size != PATH_BYTES
        || user_size != PATH_BYTES
        || wire.len() < HEADER + count * PATH_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MPTCP subflow output exceeds the gate ABI budget",
        ));
    }
    (0..count)
        .map(|index| {
            let at = HEADER + index * PATH_BYTES;
            Ok((
                address(&wire[at..at + ADDRESS_BYTES])?,
                address(&wire[at + ADDRESS_BYTES..at + PATH_BYTES])?,
            ))
        })
        .collect()
}

fn address(wire: &[u8]) -> io::Result<SocketAddr> {
    let family = u16::from_ne_bytes(wire[..2].try_into().unwrap()) as libc::c_int;
    let port = u16::from_be_bytes(wire[2..4].try_into().unwrap());
    match family {
        libc::AF_INET => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&wire[4..8]).unwrap())),
            port,
        )),
        libc::AF_INET6 => Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&wire[8..24]).unwrap()),
            port,
            u32::from_be_bytes(wire[4..8].try_into().unwrap()),
            u32::from_ne_bytes(wire[24..28].try_into().unwrap()),
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown MPTCP subflow family",
        )),
    }
}

fn option(stream: &impl AsRawFd, name: libc::c_int, wire: &mut [u8]) -> io::Result<usize> {
    let mut length = wire.len() as libc::socklen_t;
    // SAFETY: the borrowed descriptor remains owned by its live stream; the
    // bounded initialized output is writable for exactly the supplied length.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_MPTCP,
            name,
            wire.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let length = length as usize;
    if length < HEADER || length > wire.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subflow_states_are_actual_bounded_tcp_info_not_address_count() {
        let mut wire = [0_u8; HEADER + 2 * TCP_INFO_PREFIX];
        wire[4..8].copy_from_slice(&2_u32.to_ne_bytes());
        wire[8..12].copy_from_slice(&256_u32.to_ne_bytes());
        wire[12..16].copy_from_slice(&(TCP_INFO_PREFIX as u32).to_ne_bytes());
        wire[HEADER] = 1; // TCP_ESTABLISHED
        wire[HEADER + TCP_INFO_PREFIX] = 2; // TCP_SYN_SENT is not established
        assert_eq!(decode_states(&wire).unwrap(), [1, 2]);
        assert!(decode_states(&wire[..wire.len() - 1]).is_err());
        wire[4..8].copy_from_slice(&5_u32.to_ne_bytes());
        assert!(decode_states(&wire).is_err());
    }

    #[test]
    fn actual_subflow_abi_counts_paths_without_interpreting_the_request_as_success() {
        let mut wire = [0_u8; HEADER + 2 * PATH_BYTES];
        wire[4..8].copy_from_slice(&2_u32.to_ne_bytes());
        wire[8..12].copy_from_slice(&(PATH_BYTES as u32).to_ne_bytes());
        wire[12..16].copy_from_slice(&(PATH_BYTES as u32).to_ne_bytes());
        for index in 0..2 {
            for (offset, ip, port) in [
                (0, [10, 77, 0, index as u8 + 1], 50000),
                (ADDRESS_BYTES, [10, 77, 0, 3], 443),
            ] {
                let at = HEADER + index * PATH_BYTES + offset;
                wire[at..at + 2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
                wire[at + 2..at + 4].copy_from_slice(&(port as u16).to_be_bytes());
                wire[at + 4..at + 8].copy_from_slice(&ip);
            }
        }
        let result = decode_paths(&wire).unwrap();
        assert_eq!(result.len(), 2);
        assert_ne!(result[0].0, result[1].0);
        assert!(decode_paths(&wire[..wire.len() - 1]).is_err());
        wire[4..8].copy_from_slice(&5_u32.to_ne_bytes());
        assert!(decode_paths(&wire).is_err());
    }
}
