//! Read-only discovery through services already running on the system bus.
use super::{DnsBinding, MAX_METADATA_BYTES, SourceEndpoint, SourceExclusions, unavailable};
use crate::config::DnsSource;
use serde_json::Value;
use std::{
    ffi::CString,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const RESOLVE: &str = "org.freedesktop.resolve1";
const RESOLVE_PATH: &str = "/org/freedesktop/resolve1";
const RESOLVE_MANAGER: &str = "org.freedesktop.resolve1.Manager";
const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";

pub(super) fn discover(
    source: &DnsSource,
    exclusions: &SourceExclusions,
    check: &dyn Fn() -> io::Result<()>,
) -> io::Result<Vec<SourceEndpoint>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let bus = Bus { deadline, check };
    match source {
        DnsSource::System => system(&bus, exclusions),
        DnsSource::Dhcp(interface) => dhcp(&bus, interface, exclusions),
    }
}

fn system(bus: &Bus<'_>, exclusions: &SourceExclusions) -> io::Result<Vec<SourceEndpoint>> {
    let data = bus.property(RESOLVE, RESOLVE_PATH, RESOLVE_MANAGER, "DNS")?;
    let rows = array_body(&data)?;
    let mut servers = Vec::new();
    let global_tls = bus
        .property(RESOLVE, RESOLVE_PATH, RESOLVE_MANAGER, "DNSOverTLS")
        .and_then(|value| string_body(&value).map(str::to_owned))?;
    let mut policies = std::collections::HashMap::new();
    for row in rows {
        let row = row.as_array().ok_or_else(unavailable)?;
        if row.len() != 3 {
            return Err(unavailable());
        }
        let index = row[0]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(unavailable)?;
        if index == 0 {
            continue;
        } // Global servers have no physical link attribution.
        let Some(interface) = interface_name(index) else {
            continue;
        };
        if !physical_interface(&interface, exclusions) {
            continue;
        }
        let encrypted = if let Some(policy) = policies.get(&index) {
            *policy
        } else {
            let path = bus.call(
                RESOLVE,
                RESOLVE_PATH,
                RESOLVE_MANAGER,
                "GetLink",
                &["i", &index.to_string()],
            )?;
            let path = string_body(&path)?;
            let tls = bus.property(RESOLVE, path, "org.freedesktop.resolve1.Link", "DNSOverTLS")?;
            let tls = string_body(&tls)?;
            let required = if tls.is_empty() {
                global_tls.as_str()
            } else {
                tls
            } != "no";
            policies.insert(index, required);
            required
        };
        let family = row[1].as_i64().ok_or_else(unavailable)?;
        let address = decode_address(family, &row[2])?;
        let endpoint = socket_address(address, index)?;
        let server = SourceEndpoint {
            endpoint,
            binding: DnsBinding {
                interface: interface.into(),
                interface_index: std::num::NonZeroU32::new(index),
            },
            requires_encryption: encrypted,
        };
        if exclusions.permits(&server) && !servers.contains(&server) {
            servers.push(server);
        }
    }
    Ok(servers)
}

fn dhcp(
    bus: &Bus<'_>,
    interface: &str,
    exclusions: &SourceExclusions,
) -> io::Result<Vec<SourceEndpoint>> {
    super::validate_interface(interface)?;
    if !physical_interface(interface, exclusions) {
        return Err(unavailable());
    }
    let name = CString::new(interface).map_err(|_| unavailable())?;
    // SAFETY: `name` is a validated NUL-terminated interface name.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(unavailable());
    }
    let device = bus.call(NM, NM_PATH, NM, "GetDeviceByIpIface", &["s", interface])?;
    let device = string_body(&device)?;
    let state = bus.property(NM, device, "org.freedesktop.NetworkManager.Device", "State")?;
    if number_body(&state)? != 100 {
        return Err(unavailable());
    }
    let lease = bus.property(
        NM,
        device,
        "org.freedesktop.NetworkManager.Device",
        "Dhcp4Config",
    )?;
    let lease = string_body(&lease)?;
    if lease == "/" {
        return Err(unavailable());
    }
    let options = bus.property(
        NM,
        lease,
        "org.freedesktop.NetworkManager.DHCP4Config",
        "Options",
    )?;
    let dns = option(&options, "domain_name_servers").ok_or_else(unavailable)?;
    let mut servers = Vec::new();
    for address in dns.split_ascii_whitespace() {
        let address = address
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| unavailable())?;
        let server = SourceEndpoint {
            endpoint: socket_address(address, index)?,
            binding: DnsBinding {
                interface: interface.into(),
                interface_index: std::num::NonZeroU32::new(index),
            },
            requires_encryption: false,
        };
        if exclusions.permits(&server) && !servers.contains(&server) {
            servers.push(server);
        }
    }
    // Lease ownership does not prove a plaintext link policy. Require a
    // policy from the existing resolver; unknown policy is unavailable.
    let path = bus.call(
        RESOLVE,
        RESOLVE_PATH,
        RESOLVE_MANAGER,
        "GetLink",
        &["i", &index.to_string()],
    )?;
    let path = string_body(&path)?;
    let tls = bus.property(RESOLVE, path, "org.freedesktop.resolve1.Link", "DNSOverTLS")?;
    let mut tls = string_body(&tls)?.to_owned();
    if tls.is_empty() {
        tls = string_body(&bus.property(RESOLVE, RESOLVE_PATH, RESOLVE_MANAGER, "DNSOverTLS")?)?
            .to_owned();
    }
    for server in &mut servers {
        server.requires_encryption = tls != "no";
    }
    Ok(servers)
}

fn physical_interface(name: &str, exclusions: &SourceExclusions) -> bool {
    super::validate_interface(name).is_ok()
        && exclusions.interface.as_deref() != Some(name)
        && name != "lo"
        && !std::path::Path::new("/sys/class/net")
            .join(name)
            .join("tun_flags")
            .exists()
        && std::fs::read_to_string(
            std::path::Path::new("/sys/class/net")
                .join(name)
                .join("operstate"),
        )
        .is_ok_and(|state| matches!(state.trim(), "up" | "unknown"))
}
fn interface_name(index: u32) -> Option<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: the buffer has IF_NAMESIZE bytes and remains live for the call.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return None;
    }
    // SAFETY: a successful call produced a terminated interface name.
    unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}
fn socket_address(ip: IpAddr, index: u32) -> io::Result<SocketAddr> {
    let scope = match ip {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => index,
        _ => 0,
    };
    super::endpoint(ip, scope)
}
fn decode_address(family: i64, value: &Value) -> io::Result<IpAddr> {
    let bytes = value
        .as_array()
        .ok_or_else(unavailable)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(unavailable)
        })
        .collect::<io::Result<Vec<_>>>()?;
    match family {
        2 if bytes.len() == 4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        10 if bytes.len() == 16 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes.as_slice()).unwrap(),
        ))),
        _ => Err(unavailable()),
    }
}
fn body(value: &Value) -> io::Result<&Value> {
    value.get("data").ok_or_else(unavailable)
}
fn string_body(value: &Value) -> io::Result<&str> {
    let body = body(value)?;
    body.as_str()
        .or_else(|| {
            body.as_array()
                .filter(|body| body.len() == 1)?
                .first()?
                .as_str()
        })
        .ok_or_else(unavailable)
}
fn number_body(value: &Value) -> io::Result<u64> {
    let body = body(value)?;
    body.as_u64()
        .or_else(|| {
            body.as_array()
                .filter(|body| body.len() == 1)?
                .first()?
                .as_u64()
        })
        .ok_or_else(unavailable)
}
fn array_body(value: &Value) -> io::Result<&[Value]> {
    let data = body(value)?.as_array().ok_or_else(unavailable)?;
    // busctl's body contains one array argument. Accept the property form as
    // well, where the data itself is that argument.
    if let [first] = data.as_slice()
        && let Some(first) = first.as_array()
        && first.first().is_none_or(Value::is_array)
    {
        return Ok(first);
    }
    Ok(data)
}
fn option<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    let mut data = value.get("data")?;
    if let Some(array) = data.as_array()
        && array.len() == 1
        && array[0].is_object()
    {
        data = &array[0];
    }
    let value = if let Some(object) = data.as_object() {
        object.get(key)?
    } else {
        data.as_array()?.iter().find_map(|entry| {
            let pair = entry.as_array()?;
            (pair.len() == 2 && pair[0].as_str() == Some(key)).then(|| &pair[1])
        })?
    };
    value.as_str().or_else(|| string_body(value).ok())
}

struct Bus<'a> {
    deadline: Instant,
    check: &'a dyn Fn() -> io::Result<()>,
}
impl Bus<'_> {
    fn property(
        &self,
        service: &str,
        path: &str,
        interface: &str,
        property: &str,
    ) -> io::Result<Value> {
        self.run(&["get-property", service, path, interface, property])
    }
    fn call(
        &self,
        service: &str,
        path: &str,
        interface: &str,
        method: &str,
        arguments: &[&str],
    ) -> io::Result<Value> {
        let mut argv = vec!["call", service, path, interface, method];
        argv.extend_from_slice(arguments);
        self.run(&argv)
    }
    fn run(&self, argv: &[&str]) -> io::Result<Value> {
        (self.check)()?;
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let child = Command::new("/usr/bin/busctl")
            .args([
                "--system",
                "--json=short",
                "--no-pager",
                "--auto-start=no",
                "--allow-interactive-authorization=no",
                "--timeout=3s",
            ])
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut child = OwnedChild(child);
        let mut stdout = child.0.stdout.take().ok_or_else(unavailable)?;
        let mut stderr = child.0.stderr.take().ok_or_else(unavailable)?;
        nonblocking(stdout.as_raw_fd())?;
        nonblocking(stderr.as_raw_fd())?;
        let mut output = Vec::new();
        let mut errors = 0;
        loop {
            (self.check)()?;
            if Instant::now() >= self.deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            drain(&mut stdout, &mut output)?;
            discard(&mut stderr, &mut errors)?;
            if let Some(status) = child.0.try_wait()? {
                drain(&mut stdout, &mut output)?;
                discard(&mut stderr, &mut errors)?;
                if !status.success() {
                    return Err(unavailable());
                }
                return serde_json::from_slice(&output).map_err(|_| unavailable());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: fd is a live owned pipe and F_GETFL/F_SETFL use integer flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn drain(reader: &mut impl Read, output: &mut Vec<u8>) -> io::Result<()> {
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                if output
                    .len()
                    .checked_add(count)
                    .is_none_or(|size| size > MAX_METADATA_BYTES)
                {
                    return Err(unavailable());
                }
                output.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}
fn discard(reader: &mut impl Read, total: &mut usize) -> io::Result<()> {
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                *total = total
                    .checked_add(count)
                    .filter(|size| *size <= MAX_METADATA_BYTES)
                    .ok_or_else(unavailable)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn busctl_property_and_call_bodies_keep_link_and_lease_metadata() {
        // busctl get-property dumps the variant's subtree; a method reply
        // dumps an array of arguments. Dictionaries use JSON objects.
        let property = json!({"type":"a(iiay)","data":[[7,2,[10,0,0,53]]]});
        let rows = array_body(&property).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], 7);
        assert_eq!(
            decode_address(2, &rows[0][2]).unwrap(),
            "10.0.0.53".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            string_body(&json!({"type":"o","data":["/link/7"]})).unwrap(),
            "/link/7"
        );
        assert_eq!(number_body(&json!({"type":"u","data":100})).unwrap(), 100);
        let lease = json!({"type":"a{sv}","data":{
            "domain_name_servers":{"type":"s","data":"10.0.0.53 10.0.0.54"}
        }});
        assert_eq!(
            option(&lease, "domain_name_servers"),
            Some("10.0.0.53 10.0.0.54")
        );
        assert!(decode_address(2, &json!([10, 0, 0, 256])).is_err());
    }
}
