//! Windows socket binding without changing the Provider's immutable session.
use super::*;
use windows::{
    Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceAliasToLuid, ConvertInterfaceGuidToLuid,
                ConvertInterfaceLuidToIndex, ConvertInterfaceNameToLuidW,
            },
            Ndis::NET_LUID_LH,
        },
    },
    core::{GUID, PCWSTR},
};

fn interface_index(name: &str) -> io::Result<NonZeroU32> {
    let mut luid = NET_LUID_LH::default();
    let status = if let Ok(guid) = GUID::try_from(name.trim_matches(['{', '}'])) {
        // SAFETY: both SDK values remain live for the synchronous conversion.
        unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) }
    } else {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: the interface string is NUL terminated and the output is live.
        let alias = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
        if alias == NO_ERROR {
            alias
        } else {
            // Also accept the canonical system interface name.
            unsafe { ConvertInterfaceNameToLuidW(PCWSTR(wide.as_ptr()), &mut luid) }
        }
    };
    if status != NO_ERROR {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "outbound interface is unavailable",
        ));
    }
    let mut index = 0;
    // SAFETY: luid was initialized by a successful conversion above.
    if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } != NO_ERROR {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "outbound interface is unavailable",
        ));
    }
    NonZeroU32::new(index).ok_or_else(|| io::ErrorKind::NotFound.into())
}

impl Dialer {
    pub(super) fn apply_configured_interface(
        &self,
        socket: RawSocket,
        destination: SocketAddr,
    ) -> io::Result<()> {
        if destination.ip().is_loopback() {
            return Ok(());
        }
        let Some(name) = &self.egress.interface else {
            return Ok(());
        };
        #[cfg(feature = "windows-uwp")]
        if self.dns_binding.is_some() {
            // for_dns_source already validated the authoritative Provider
            // adapter; its explicit source binding wins over global defaults.
            return Ok(());
        }
        let index = interface_index(name)?;
        #[cfg(feature = "windows-uwp")]
        if let Some(binding) = self.interface_binding {
            if let Some(adapter) = &self.physical_adapter {
                if interface_index(adapter)? != index {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "interface-name conflicts with the physical network binding",
                    ));
                }
                return Ok(());
            }
            let bound = if destination.is_ipv6() {
                binding.ipv6.map(|(_, index)| index)
            } else {
                binding.ipv4.map(|(_, index)| index)
            };
            if bound != Some(index) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "interface-name conflicts with the physical network binding",
                ));
            }
            // apply_interface_binding already set the Provider's source/index.
            return Ok(());
        }
        let ipv6 = destination.is_ipv6();
        let (level, option) = if ipv6 {
            (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP.0, IP_UNICAST_IF)
        };
        let value = interface_option_value(index, ipv6);
        let socket = usize::try_from(socket).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: the owned socket is live and the required DWORD is four bytes.
        if unsafe { setsockopt(SOCKET(socket), level, option, Some(&value)) } == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
        }
        Ok(())
    }
}
