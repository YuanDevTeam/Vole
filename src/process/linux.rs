//! Linux procfs socket tables: exact local AND remote tuple, then inode ownership.
use super::*;
use std::{
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
};

fn bounded(path: &std::path::Path, limit: usize) -> io::Result<String> {
    let mut value = String::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_string(&mut value)?;
    if value.len() > limit {
        return Err(io::Error::other("process table exceeds budget"));
    }
    Ok(value)
}
fn address(value: &str) -> Option<SocketAddr> {
    let (host, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let host = match host.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(host, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut bytes = [0; 16];
            for (word, out) in host
                .as_bytes()
                .chunks_exact(8)
                .zip(bytes.chunks_exact_mut(4))
            {
                out.copy_from_slice(
                    &u32::from_str_radix(std::str::from_utf8(word).ok()?, 16)
                        .ok()?
                        .to_ne_bytes(),
                );
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(host, port))
}
fn socket_row(text: &str, query: Query, budget: &mut Budget<'_>) -> io::Result<Option<(u32, u64)>> {
    let mut found = None;
    for row in text.lines().skip(1) {
        budget.visit()?;
        let mut fields = row.split_ascii_whitespace();
        let Some(local) = fields.nth(1) else {
            continue;
        };
        let Some(remote) = fields.next() else {
            continue;
        };
        if address(local) != Some(query.source) || address(remote) != Some(query.destination) {
            continue;
        }
        // State, queues, timer, retransmits precede the kernel UID.
        let Some(uid) = fields.nth(4).and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(inode) = fields
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
        else {
            continue;
        };
        if found.is_some() {
            return Ok(None);
        }
        found = Some((uid, inode));
    }
    Ok(found)
}
fn start_time(path: &std::path::Path) -> Option<u64> {
    let stat = bounded(&path.join("stat"), 4096).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_ascii_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
pub(super) fn platform(query: Query, budget: &mut Budget<'_>) -> io::Result<Identity> {
    let table = match (query.network, query.source.is_ipv6()) {
        (Network::Tcp, false) => "tcp",
        (Network::Tcp, true) => "tcp6",
        (Network::Udp, false) => "udp",
        (Network::Udp, true) => "udp6",
    };
    let text = match bounded(&std::path::Path::new("/proc/net").join(table), MAX_TABLE) {
        Ok(value) => value,
        Err(_) => return Ok(Identity::default()),
    };
    let Some((uid, inode)) = socket_row(&text, query, budget)? else {
        return Ok(Identity::default());
    };
    drop(text);
    let mut identity = Identity {
        uid: Some(uid),
        ..Default::default()
    };
    let expected = format!("socket:[{inode}]");
    let mut owner = None;
    for entry in fs::read_dir("/proc")? {
        budget.visit()?;
        let Ok(entry) = entry else {
            continue;
        };
        if entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let path = entry.path();
        if fs::metadata(&path)
            .ok()
            .is_none_or(|metadata| metadata.uid() != uid)
        {
            continue;
        }
        let Some(start) = start_time(&path) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(path.join("fd")) else {
            continue;
        };
        for fd in fds {
            budget.visit()?;
            let Ok(fd) = fd else {
                continue;
            };
            if fs::read_link(fd.path()).ok().as_deref() != Some(std::path::Path::new(&expected)) {
                continue;
            }
            let Ok(exe) = fs::read_link(path.join("exe")) else {
                continue;
            };
            budget.check()?;
            if start_time(&path) != Some(start)
                || fs::read_link(fd.path()).ok().as_deref() != Some(std::path::Path::new(&expected))
            {
                continue;
            }
            let Some(value) = exe
                .to_str()
                .and_then(|value| Identity::from_path(value.to_owned()))
            else {
                continue;
            };
            if owner.as_ref().is_some_and(|old| old != &path) {
                return Ok(Identity {
                    uid: Some(uid),
                    ..Default::default()
                });
            }
            owner = Some(path.clone());
            identity.name = value.name;
            identity.path = value.path;
            break;
        }
    }
    // Revalidate the kernel tuple/inode after walking mutable /proc entries.
    let current = bounded(&std::path::Path::new("/proc/net").join(table), MAX_TABLE).ok();
    if current
        .as_deref()
        .map(|text| socket_row(text, query, budget))
        .transpose()?
        .flatten()
        != Some((uid, inode))
    {
        return Ok(Identity::default());
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proc_socket_oracle_requires_full_tuple_and_unique_inode() {
        let query = Query {
            network: Network::Tcp,
            source: "127.0.0.1:1234".parse().unwrap(),
            destination: "192.0.2.3:443".parse().unwrap(),
        };
        let row = "0: 0100007F:04D2 030200C0:01BB 01 0:0 0:0 0 1001 0 987 0";
        let check = || Ok(());
        let mut budget = Budget {
            check: &check,
            until: Instant::now() + LOOKUP_TIME,
            entries: MAX_ENTRIES,
        };
        assert_eq!(
            socket_row(&format!("header\n{row}\n"), query, &mut budget).unwrap(),
            Some((1001, 987))
        );
        let wrong = row.replace("0100007F", "0200007F");
        assert_eq!(
            socket_row(&format!("header\n{wrong}\n"), query, &mut budget).unwrap(),
            None
        );
        assert_eq!(
            socket_row(&format!("header\n{row}\n{row}\n"), query, &mut budget).unwrap(),
            None
        );
    }
}
