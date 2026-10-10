//! Session-Host discovery for the Provider's immutable physical adapter GUID.
use super::{DnsNetworkUpdate, MAX_METADATA_BYTES, SystemDnsServer, unavailable};
use std::{
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows::{
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
        NetworkManagement::IpHelper::{
            DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION3, DNS_INTERFACE_SETTINGS3,
            DNS_SETTING_DOH, DNS_SETTING_DOH_PROFILE, FreeInterfaceDnsSettings,
            GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, GetInterfaceDnsSettings,
            IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
    },
    core::GUID,
};

pub(crate) fn snapshot(
    adapter_name: &str,
    check: &dyn Fn() -> io::Result<()>,
) -> io::Result<DnsNetworkUpdate> {
    let guid = GUID::try_from(adapter_name).map_err(|_| unavailable())?;
    check()?;
    let mut settings = Settings(DNS_INTERFACE_SETTINGS3 {
        Version: DNS_INTERFACE_SETTINGS_VERSION3,
        ..Default::default()
    });
    // SAFETY: v3 layout starts with DNS_INTERFACE_SETTINGS, and is live here.
    let status = unsafe { GetInterfaceDnsSettings(guid, (&raw mut settings.0).cast()) };
    if status != NO_ERROR {
        return Err(unavailable());
    }
    let encrypted = settings.0.cServerProperties != 0
        || settings.0.cProfileServerProperties != 0
        || settings.0.Flags & u64::from(DNS_SETTING_DOH | DNS_SETTING_DOH_PROFILE) != 0;
    check()?;
    let mut storage = vec![0_usize; (15 * 1024_usize).div_ceil(size_of::<usize>())];
    for _ in 0..3 {
        check()?;
        let mut length =
            u32::try_from(storage.len() * size_of::<usize>()).map_err(|_| unavailable())?;
        // SAFETY: the aligned storage remains live while the OS list is read.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                GET_ADAPTERS_ADDRESSES_FLAGS(0),
                None,
                Some(storage.as_mut_ptr().cast()),
                &mut length,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW.0 {
            if length as usize > MAX_METADATA_BYTES {
                return Err(unavailable());
            }
            storage.resize(
                (length as usize)
                    .div_ceil(size_of::<usize>())
                    .max(storage.len() + 1),
                0,
            );
            continue;
        }
        if status != NO_ERROR.0 {
            return Err(unavailable());
        }
        let mut current = storage.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            check()?;
            // SAFETY: GetAdaptersAddresses initialized the linked entries.
            let adapter = unsafe { &*current };
            if !adapter.AdapterName.is_null() {
                // SAFETY: this terminated string belongs to live storage.
                let name = unsafe { adapter.AdapterName.to_string() }.map_err(|_| unavailable())?;
                if name
                    .trim_matches(['{', '}'])
                    .eq_ignore_ascii_case(adapter_name)
                {
                    let mut servers = Vec::new();
                    let mut dns = adapter.FirstDnsServerAddress;
                    while !dns.is_null() {
                        check()?;
                        // SAFETY: DNS entries and address pointers belong to the same live storage.
                        let dns_entry = unsafe { &*dns };
                        let address = dns_entry.Address;
                        if !address.lpSockaddr.is_null() {
                            // SAFETY: the pointer identifies at least the returned sockaddr header.
                            let family = unsafe { (*address.lpSockaddr).sa_family };
                            let value = if family == AF_INET
                                && address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32
                            {
                                // SAFETY: the family and length identify SOCKADDR_IN.
                                let address = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
                                // SAFETY: S_un_b is the IPv4 octet view.
                                let bytes = unsafe { address.sin_addr.S_un.S_un_b };
                                Some((
                                    IpAddr::V4(Ipv4Addr::new(
                                        bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                                    )),
                                    0,
                                ))
                            } else if family == AF_INET6
                                && address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32
                            {
                                // SAFETY: family/length identify SOCKADDR_IN6 and its address/scope unions.
                                let address =
                                    unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
                                Some((
                                    IpAddr::V6(Ipv6Addr::from(unsafe { address.sin6_addr.u.Byte })),
                                    unsafe { address.Anonymous.sin6_scope_id },
                                ))
                            } else {
                                None
                            };
                            if let Some((address, scope)) = value
                                && super::endpoint(address, scope).is_ok()
                            {
                                let server = SystemDnsServer {
                                    address,
                                    interface: adapter_name.to_owned(),
                                    scope_id: scope,
                                    // The read API requires empty input Flags;
                                    // its default settings cover IPv4. Without
                                    // a proven IPv6 policy, do not downgrade an
                                    // IPv6 DNS server to UDP/TCP.
                                    requires_encryption: encrypted || address.is_ipv6(),
                                };
                                if !servers.contains(&server) {
                                    servers.push(server);
                                }
                            }
                        }
                        dns = dns_entry.Next;
                    }
                    let update = DnsNetworkUpdate {
                        generation: 1,
                        system: servers,
                        dhcp: Vec::new(),
                    };
                    update.validate()?;
                    return Ok(update);
                }
            }
            current = adapter.Next;
        }
        return Err(unavailable());
    }
    Err(unavailable())
}
struct Settings(DNS_INTERFACE_SETTINGS3);
impl Drop for Settings {
    fn drop(&mut self) {
        // SAFETY: API-owned fields use its paired deallocator, including a failed call.
        unsafe { FreeInterfaceDnsSettings((&raw mut self.0).cast::<DNS_INTERFACE_SETTINGS>()) };
    }
}
