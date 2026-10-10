//! Bounded, streamed access to one member of the user's offline rules bundle.
use super::bundle_limits::{CheckedSource, inspect, inspect_block};
use std::{
    io::{self, Read, Seek},
    path::Path,
};
use tokio_util::sync::CancellationToken;

const MAX_MEMBER: u64 = 64 * 1024 * 1024;

pub(crate) fn valid_member(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.contains('\0')
        && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

pub(crate) fn read_member(
    root: &Path,
    name: &str,
    configured_limit: u64,
    cancellation: &CancellationToken,
) -> io::Result<Vec<u8>> {
    let path = super::cache::resource_path(root, "BundleMRS.7z", false)?;
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("rule bundle must be a regular file"));
    }
    decode_member(file, name, configured_limit, cancellation)
}

fn decode_member(
    source: impl Read + Seek,
    name: &str,
    configured_limit: u64,
    cancellation: &CancellationToken,
) -> io::Result<Vec<u8>> {
    if !valid_member(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bundle member",
        ));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let flag = || cancellation.is_cancelled();
    let mut source = CheckedSource::new(source, &flag)?;
    let admission = inspect(&mut source)?;
    let password = sevenz_rust2::Password::empty();
    // Header dictionary admission occurs before this call allocates a decoder.
    let archive = sevenz_rust2::Archive::read(&mut source, &password).map_err(|_| invalid())?;
    source.check()?;
    let mut matches = archive
        .files
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.name == name);
    let (file_index, target) = matches
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "bundle member unavailable"))?;
    if matches.next().is_some() || !target.has_stream || target.is_directory || target.is_anti_item
    {
        return Err(invalid());
    }
    let limit = if configured_limit == 0 {
        MAX_MEMBER
    } else {
        configured_limit.min(MAX_MEMBER)
    };
    if target.size > limit {
        return Err(invalid());
    }
    let block = archive
        .stream_map
        .file_block_index
        .get(file_index)
        .copied()
        .flatten()
        .ok_or_else(invalid)?;
    // Charge retained output together with this decode's dictionary/metadata.
    inspect_block(&archive, block, admission, target.size)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(usize::try_from(target.size).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let mut decoded = 0u64;
    let mut found = false;
    sevenz_rust2::BlockDecoder::new(1, block, &archive, &password, &mut source)
        .for_each_entries(&mut |entry, input| {
            let keep = entry.name == name;
            let mut chunk = [0; 8192];
            loop {
                if cancellation.is_cancelled() {
                    return Err(io::Error::from(io::ErrorKind::ConnectionAborted).into());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::from(io::ErrorKind::TimedOut).into());
                }
                let count = input.read(&mut chunk)?;
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::from(io::ErrorKind::TimedOut).into());
                }
                if count == 0 {
                    break;
                }
                decoded = decoded.checked_add(count as u64).ok_or_else(invalid)?;
                if decoded > 256 * 1024 * 1024 || keep && output.len() as u64 + count as u64 > limit
                {
                    return Err(invalid().into());
                }
                if keep {
                    output.extend_from_slice(&chunk[..count]);
                }
            }
            if keep {
                found = true;
            }
            // Reading to EOF verifies this member's CRC before stopping. Prefix
            // members have been streamed and discarded, never retained.
            Ok(!keep)
        })
        .map_err(|_| invalid())?;
    source.check()?;
    if !found || output.len() as u64 != target.size {
        return Err(invalid());
    }
    Ok(output)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or over-budget rule bundle",
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::config::{
        RuleCollection,
        providers::{RuleBehavior, RuleFormat},
    };
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, SourceReader};
    use std::io::Cursor;

    pub(crate) fn mrs() -> Vec<u8> {
        let mut wire = b"MRS\x01".to_vec();
        wire.push(1);
        wire.extend_from_slice(&1i64.to_be_bytes());
        wire.extend_from_slice(&0i64.to_be_bytes());
        wire.push(1);
        wire.extend_from_slice(&1i64.to_be_bytes());
        for ip in [
            std::net::Ipv4Addr::new(192, 0, 2, 0),
            std::net::Ipv4Addr::new(192, 0, 2, 255),
        ] {
            wire.extend_from_slice(&ip.to_ipv6_mapped().octets());
        }
        zstd::encode_all(wire.as_slice(), 1).unwrap()
    }

    pub(crate) fn archive(member: &[u8], encoded: bool) -> Vec<u8> {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.set_encrypt_header(encoded);
        writer
            .push_archive_entries(
                vec![
                    ArchiveEntry::new_file("prefix"),
                    ArchiveEntry::new_file("rules/cn.mrs"),
                ],
                vec![
                    SourceReader::new(Cursor::new(b"discard without retaining".to_vec())),
                    SourceReader::new(Cursor::new(member.to_vec())),
                ],
            )
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn bundle_member_streams_real_mrs_and_observes_output_and_cancellation() {
        let member = mrs();
        for encoded in [false, true] {
            let wire = archive(&member, encoded);
            let cancellation = CancellationToken::new();
            let data = decode_member(Cursor::new(&wire), "rules/cn.mrs", 0, &cancellation).unwrap();
            assert_eq!(data, member);
            let rules =
                RuleCollection::parse(&data, RuleBehavior::Ipcidr, RuleFormat::Mrs).unwrap();
            assert!(rules.matches_ip(
                "192.0.2.1".parse().unwrap(),
                &crate::routing::EmptyGeoMatcher
            ));
            assert!(!rules.matches_ip(
                "198.51.100.1".parse().unwrap(),
                &crate::routing::EmptyGeoMatcher
            ));
            assert!(
                decode_member(
                    Cursor::new(&wire),
                    "rules/cn.mrs",
                    member.len() as u64 - 1,
                    &cancellation
                )
                .is_err()
            );
            cancellation.cancel();
            assert!(decode_member(Cursor::new(&wire), "rules/cn.mrs", 0, &cancellation).is_err());
        }
    }
}
