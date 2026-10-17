use std::{fs, sync::Arc, time::Duration};

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    config::{Config, Network, RuleCollection},
    dns::fallback::Filter,
    routing::{RoutingContext, matches_rule},
    session::Destination,
};

const COUNTRY: &[u8] = include_bytes!("../../tests/fixtures/geodata/Country-Test.mmdb");
const SING: &[u8] = include_bytes!("../../tests/fixtures/geodata/Sing-Test.mmdb");
const META: &[u8] = include_bytes!("../../tests/fixtures/geodata/Meta-Test.mmdb");

fn config() -> Config {
    Config::parse_yaml(
        br#"
dns:
  enable: true
  fallback: [1.1.1.1]
  fallback-filter: {geoip: true, geoip-code: CN}
rule-providers:
  geo: {type: inline, behavior: classical, payload: ["GEOIP,CN"]}
rules:
  - GEOIP,CN,REJECT,no-resolve
  - SRC-GEOIP,CN,DIRECT
  - GEOIP,!CN,REJECT,no-resolve
  - GEOIP,US,DIRECT,no-resolve
  - RULE-SET,geo,DIRECT
  - MATCH,DIRECT
"#,
    )
    .unwrap()
}

fn stage(session: &GeoUpdateSession, bytes: &[u8]) -> ([u8; 32], u64) {
    fs::write(session.temporary_path(), bytes).unwrap();
    (Sha256::digest(bytes).into(), bytes.len() as u64)
}

// Independently remove the one description entry from the existing synthetic
// MMDB fixture. Tree/data/marker bytes keep their exact offsets.
fn empty_description(fixture: &[u8]) -> Vec<u8> {
    let description = b"\xe1\x42en\x56Vole synthetic country";
    let start = fixture
        .windows(description.len())
        .position(|value| value == description)
        .unwrap();
    let mut bytes = fixture.to_vec();
    bytes.splice(start..start + description.len(), [0xe0]);
    bytes
}

#[test]
fn country_mmdb_empty_description_keeps_original_bytes_metadata_and_lookup() {
    for (fixture, filename) in [(SING, "geoip.db"), (META, "geoip.metadb")] {
        let original = empty_description(fixture);
        let metadata = {
            let reader = maxminddb::Reader::from_source(original.as_slice()).unwrap();
            assert!(reader.metadata().description.is_empty());
            assert!(reader.verify().is_err());
            reader.metadata().clone()
        };
        let mut bytes = original.clone();
        bytes.reserve_exact(512);
        let pointer = bytes.as_ptr();
        country::verify_country_mmdb(&mut bytes).unwrap();
        assert_eq!(bytes, original);
        assert_eq!(bytes.as_ptr(), pointer);
        let reader = maxminddb::Reader::from_source(bytes.as_slice()).unwrap();
        assert_eq!(reader.metadata(), &metadata);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(filename);
        fs::write(&path, &original).unwrap();
        let manager =
            GeoDataManager::open(directory.path().join("geodata"), Duration::from_secs(3600))
                .unwrap();
        let registration = manager
            .register(GeoRequirements::for_config(&config()).unwrap())
            .unwrap();
        assert!(registration.initial_report().geoip.available);
        let snapshot = registration.matcher().snapshot();
        assert!(snapshot.matches_geoip("cn", "1.2.3.4".parse().unwrap()));
        assert!(snapshot.matches_geoip("cn", "2001:db8::1".parse().unwrap()));
        assert!(snapshot.matches_geoip("!cn", "8000::1".parse().unwrap()));
        assert_eq!(fs::read(path).unwrap(), original);
    }
    // An empty description is not a general exception for other DB schemas.
    let mut country = empty_description(COUNTRY);
    let original = country.clone();
    assert!(country::verify_country_mmdb(&mut country).is_err());
    assert_eq!(country, original);
}

#[test]
fn country_mmdb_empty_description_still_rejects_corrupt_tree_separator_and_data() {
    for fixture in [SING, META] {
        let valid = empty_description(fixture);
        let metadata = maxminddb::Reader::from_source(valid.as_slice())
            .unwrap()
            .metadata()
            .clone();
        let tree_bytes = metadata.node_count as usize * usize::from(metadata.record_size) / 4;
        for corruption in ["tree", "separator", "data-pointer", "utf8"] {
            let mut bytes = valid.clone();
            match corruption {
                "tree" => bytes[..3].copy_from_slice(&[0xff; 3]),
                "separator" => bytes[tree_bytes] = 1,
                // Small pointer 0 resolves to its own record: verification
                // must follow pointer targets rather than use IgnoredAny.
                "data-pointer" => {
                    bytes[tree_bytes + 16..tree_bytes + 18].copy_from_slice(&[0x20, 0])
                }
                "utf8" => {
                    // CN string is the first data record for sing, and the
                    // first element of the root array for Meta.
                    let offset = if metadata.database_type == "sing-geoip" {
                        17
                    } else {
                        19
                    };
                    bytes[tree_bytes + offset] = 0xff;
                }
                _ => unreachable!(),
            }
            let original = bytes.clone();
            assert!(
                country::verify_country_mmdb(&mut bytes).is_err(),
                "{corruption}"
            );
            assert_eq!(bytes, original, "{corruption}");
            assert_eq!(
                maxminddb::Reader::from_source(bytes.as_slice())
                    .unwrap()
                    .metadata(),
                &metadata
            );
        }
    }
}

#[test]
fn country_mmdb_schemas_share_route_source_collection_and_fallback() {
    for fixture in [COUNTRY, SING, META] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cOuNtRy.MmDb"), fixture).unwrap();
        let manager =
            GeoDataManager::open(dir.path().join("geodata"), Duration::from_secs(3600)).unwrap();
        let config = config();
        assert!(!config.geodata_update.as_ref().unwrap().geodata_mode);
        let registration = manager
            .register(GeoRequirements::for_config(&config).unwrap())
            .unwrap();
        assert!(registration.initial_report().geoip.available);
        let snapshot = registration.matcher().snapshot();
        assert!(snapshot.country.is_some() && snapshot.ips.is_empty());
        for address in ["1.2.3.4", "2001:db8::1"] {
            let destination = Destination::Ip(
                format!(
                    "{}:443",
                    if address.contains(':') {
                        format!("[{address}]")
                    } else {
                        address.into()
                    }
                )
                .parse()
                .unwrap(),
            );
            let mut context = RoutingContext::new(Network::Tcp, &destination).unwrap();
            context.set_source("[2001:db8::2]:12345".parse().unwrap());
            assert_eq!(
                matches_rule(&config.rules[0], &context, snapshot.as_ref()),
                Ok(true)
            );
            assert_eq!(
                matches_rule(&config.rules[1], &context, snapshot.as_ref()),
                Ok(true)
            );
            assert_eq!(
                matches_rule(&config.rules[2], &context, snapshot.as_ref()),
                Ok(false)
            );
            let ip = address.parse().unwrap();
            assert!(!Filter::new(&config.dns.fallback).address(ip, snapshot.as_ref()));
            let collection = RuleCollection::from_payload(
                vec!["GEOIP,CN".into()],
                crate::config::providers::RuleBehavior::Classical,
            )
            .unwrap();
            assert!(
                collection
                    .matches_ip(
                        ip,
                        snapshot.as_ref(),
                        &crate::config::RuleDecision::default()
                    )
                    .unwrap()
            );
        }
        let other = "8000::1".parse().unwrap();
        assert!(snapshot.matches_geoip("us", other));
        assert!(snapshot.matches_geoip("!cn", other));
        assert!(Filter::new(&config.dns.fallback).address(other, snapshot.as_ref()));
    }
}

#[test]
fn country_mmdb_discovery_uses_first_name_and_preserves_missing_semantics() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("geoip.metadb"), COUNTRY).unwrap();
    fs::write(dir.path().join("COUNTRY.MMDB"), b"broken").unwrap();
    let manager =
        GeoDataManager::open(dir.path().join("geodata"), Duration::from_secs(3600)).unwrap();
    let registration = manager
        .register(GeoRequirements::for_config(&config()).unwrap())
        .unwrap();
    assert!(!registration.initial_report().geoip.available);
    assert!(
        !registration
            .matcher()
            .matches_geoip("!cn", "8000::1".parse().unwrap())
    );
    let session = manager.begin_update(GeoDataKind::GeoIp).unwrap();
    assert_eq!(
        session.temporary_path().file_name().unwrap(),
        "COUNTRY.MMDB"
    );
    drop(session);
    drop(registration);
    fs::remove_file(dir.path().join("COUNTRY.MMDB")).unwrap();
    fs::remove_file(dir.path().join("geoip.metadb")).unwrap();
    let registration = manager
        .register(GeoRequirements::for_config(&config()).unwrap())
        .unwrap();
    assert!(!registration.initial_report().geoip.available);
    let update = manager.begin_update(GeoDataKind::GeoIp).unwrap();
    assert_eq!(update.temporary_path().file_name().unwrap(), "geoip.metadb");
    let (hash, size) = stage(&update, META);
    assert!(update.commit(None, hash, size).unwrap().geoip_available);
    assert_eq!(fs::read(dir.path().join("geoip.metadb")).unwrap(), META);
    assert!(!manager.store_dir().join("geoip.metadb").exists());
}

#[test]
fn country_mmdb_update_rejects_bad_candidate_and_drains_before_publish() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("GeoIP.DB");
    fs::write(&path, COUNTRY).unwrap();
    let manager =
        GeoDataManager::open(dir.path().join("geodata"), Duration::from_secs(3600)).unwrap();
    let registration = manager
        .register(GeoRequirements::for_config(&config()).unwrap())
        .unwrap();
    let matcher = registration.matcher();
    let old = matcher.snapshot();
    let update = manager.begin_update(GeoDataKind::GeoIp).unwrap();
    let (hash, size) = stage(&update, b"broken");
    assert!(update.commit(None, hash, size).is_err());
    assert!(Arc::ptr_eq(&old, &matcher.snapshot()));
    assert_eq!(fs::read(&path).unwrap(), COUNTRY);

    let update = manager.begin_update(GeoDataKind::GeoIp).unwrap();
    let (hash, size) = stage(&update, META);
    let cancellation = CancellationToken::new();
    let token = cancellation.clone();
    let worker =
        std::thread::spawn(move || update.commit_with_cancellation(None, hash, size, &token));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while matcher.geoip_available("cn") && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(!matcher.geoip_available("cn"));
    cancellation.cancel();
    assert!(matches!(
        worker.join().unwrap(),
        Err(GeoDataManagerError::Cancelled)
    ));
    assert!(Arc::ptr_eq(&old, &matcher.snapshot()));
    assert_eq!(fs::read(&path).unwrap(), COUNTRY);
    drop(old);
    let update = manager.begin_update(GeoDataKind::GeoIp).unwrap();
    let (hash, size) = stage(&update, META);
    assert!(
        update
            .commit(Some("new".into()), hash, size)
            .unwrap()
            .geoip_available
    );
    assert_eq!(fs::read(&path).unwrap(), META);
    assert!(matcher.matches_geoip("cn", "1.2.3.4".parse().unwrap()));
}

#[test]
fn country_mmdb_mode_changes_do_not_reuse_dat_etag_for_the_same_url() {
    let dir = tempfile::tempdir().unwrap();
    let manager =
        GeoDataManager::open(dir.path().join("geodata"), Duration::from_secs(3600)).unwrap();
    let registration = manager
        .register(GeoRequirements::for_config(&config()).unwrap())
        .unwrap();
    let url = "https://assets.example.test/shared";
    let lease = registration.updater_lease();
    let update = manager
        .begin_update_for_active_registration(
            &lease,
            GeoDataKind::GeoIp,
            url,
            std::time::SystemTime::now(),
        )
        .unwrap()
        .unwrap();
    let (hash, size) = stage(&update, COUNTRY);
    update.commit(Some("country".into()), hash, size).unwrap();
    drop(registration);
    let mut config = config();
    config.geodata_update.as_mut().unwrap().geodata_mode = true;
    let registration = manager
        .register(GeoRequirements::for_config(&config).unwrap())
        .unwrap();
    let update = manager
        .begin_update_for_active_registration(
            &registration.updater_lease(),
            GeoDataKind::GeoIp,
            url,
            std::time::SystemTime::now(),
        )
        .unwrap()
        .unwrap();
    assert!(update.request_etag().is_none());
    assert_eq!(
        update.temporary_path().file_name().unwrap(),
        GEOIP_FILE_NAME
    );
}

// Independent MMDB tree writer: routes and aliases share data offsets, exactly
// as real Meta databases do. Reuse only the existing fixture's metadata fields.
fn meta_projection_fixture(
    ipv6: bool,
    routes: &[(&str, u8, usize)],
    records: &[&[u8]],
    aliases: &[(&str, u8, &str, u8)],
) -> Vec<u8> {
    #[derive(Clone, Copy)]
    enum Edge {
        Empty,
        Node(usize),
        Record(usize),
    }
    fn bits(address: &str) -> (u128, u8) {
        match address.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
            std::net::IpAddr::V6(address) => (u128::from(address), 128),
        }
    }
    fn parent(nodes: &mut Vec<[Edge; 2]>, address: &str, prefix: u8) -> (usize, usize) {
        let (address, width) = bits(address);
        let mut node = 0;
        for bit in 0..prefix - 1 {
            let branch = ((address >> (width - bit - 1)) & 1) as usize;
            node = match nodes[node][branch] {
                Edge::Node(next) => next,
                Edge::Empty => {
                    let next = nodes.len();
                    nodes.push([Edge::Empty; 2]);
                    nodes[node][branch] = Edge::Node(next);
                    next
                }
                Edge::Record(_) => panic!("route overlaps another route"),
            };
        }
        (node, ((address >> (width - prefix)) & 1) as usize)
    }
    let mut nodes = vec![[Edge::Empty; 2]];
    for &(address, prefix, record) in routes {
        let (node, branch) = parent(&mut nodes, address, prefix);
        nodes[node][branch] = Edge::Record(record);
    }
    for &(address, prefix, target, target_prefix) in aliases {
        let (target_node, target_branch) = parent(&mut nodes, target, target_prefix);
        let Edge::Node(target) = nodes[target_node][target_branch] else {
            panic!("alias target must be a tree node")
        };
        let (node, branch) = parent(&mut nodes, address, prefix);
        nodes[node][branch] = Edge::Node(target);
    }
    let mut offsets = Vec::new();
    let mut data = Vec::new();
    for record in records {
        offsets.push(data.len());
        data.extend_from_slice(record);
    }
    let mut bytes = Vec::new();
    for node in &nodes {
        for edge in node {
            let pointer = match edge {
                Edge::Empty => nodes.len(),
                Edge::Node(node) => *node,
                Edge::Record(record) => nodes.len() + 16 + offsets[*record],
            };
            assert!(pointer < 1 << 24);
            bytes.extend_from_slice(&(pointer as u32).to_be_bytes()[1..]);
        }
    }
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&data);
    let marker = b"\xab\xcd\xefMaxMind.com";
    let start = META
        .windows(marker.len())
        .position(|part| part == marker)
        .unwrap();
    let mut metadata = META[start..].to_vec();
    let at = metadata
        .windows(10)
        .position(|part| part == b"node_count")
        .unwrap()
        + 10;
    let count = u32::try_from(nodes.len()).unwrap().to_be_bytes();
    metadata.splice(at..at + 2, [0xc4].into_iter().chain(count));
    if !ipv6 {
        let at = metadata
            .windows(10)
            .position(|part| part == b"ip_version")
            .unwrap()
            + 11;
        metadata[at] = 4;
    }
    bytes.extend_from_slice(&metadata);
    maxminddb::Reader::from_source(bytes.as_slice())
        .unwrap()
        .verify()
        .unwrap();
    bytes
}

// Decode with independent serde-owned values for parity with the unprojected
// official reader, including invalid typed records and no-record inversion.
fn meta_reader_matches(
    reader: &maxminddb::Reader<&[u8]>,
    selector: &str,
    address: std::net::IpAddr,
) -> bool {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Codes {
        One(String),
        Many(Vec<String>),
    }
    let Ok(record) = reader.lookup(address) else {
        return false;
    };
    let Ok(codes) = record.decode::<Codes>() else {
        return false;
    };
    let code = selector
        .strip_prefix('!')
        .unwrap_or(selector)
        .to_ascii_lowercase();
    let matched = match codes {
        Some(Codes::One(value)) => value == code,
        Some(Codes::Many(values)) => values.contains(&code),
        None => false,
    };
    matched != selector.starts_with('!')
}

#[test]
fn country_meta_projection_preserves_multicode_aliases_and_random_lookup_parity() {
    let bytes = meta_projection_fixture(
        true,
        &[
            ("::102:300", 120, 0),
            ("::808:800", 120, 1),
            ("2400:3200::", 32, 0),
            ("8000::", 1, 1),
            ("4000::", 2, 2),
            ("3000::", 4, 3),
        ],
        &[
            b"\x02\x04\x42cn\x47private",
            b"\x42us",
            b"\x00\x04",
            b"\x42CN",
        ],
        &[
            ("::ffff:0:0", 96, "::", 96),
            ("2002::", 16, "::", 96),
            ("2001::", 32, "::", 96),
        ],
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("geoip.metadb");
    fs::write(&path, &bytes).unwrap();
    let selectors = ["cn", "!cn", "private", "!private", "us", "zz", "!zz"].map(String::from);
    let database = country::CountryDb::load(&path, &selectors).unwrap();
    assert!(
        database.capacity() < bytes.len(),
        "projection must replace owned file bytes"
    );
    let cn = country::CountryDb::load(&path, &["cn".into()]).unwrap();
    let both = country::CountryDb::load(&path, &["cn".into(), "!cn".into()]).unwrap();
    assert_eq!(
        both.capacity() - cn.capacity(),
        std::mem::size_of::<String>() + 3
    );
    assert!(database.available("!ZZ"));
    assert!(!database.available("other"));
    let reader = maxminddb::Reader::from_source(bytes.as_slice()).unwrap();
    let mut addresses = [
        "1.2.2.255",
        "1.2.3.0",
        "1.2.3.255",
        "1.2.4.0",
        "8.8.8.8",
        "0.0.0.0",
        "255.255.255.255",
        "::102:304",
        "::ffff:102:304",
        "2002:102:304::",
        "2001:0:102:304::",
        "::ffff:102:2ff",
        "2002:102:400::",
        "2001:0:102:400::",
        "::",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2400:31ff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2400:3200::",
        "2400:3200:ffff:ffff:ffff:ffff:ffff:ffff",
        "2400:3201::",
        "3000::1",
        "4000::1",
        "6000::1",
        "8000::1",
    ]
    .map(|value| value.parse::<std::net::IpAddr>().unwrap())
    .to_vec();
    let mut state = 0x1234_5678_9abc_def0_u64;
    for _ in 0..512 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        addresses.push(std::net::Ipv4Addr::from(state as u32).into());
        addresses.push(
            std::net::Ipv6Addr::from((u128::from(state) << 64) | u128::from(state.rotate_left(23)))
                .into(),
        );
    }
    for address in addresses {
        for selector in selectors.iter().map(String::as_str).chain(["CN", "!CN"]) {
            assert_eq!(
                database.matches(selector, address),
                meta_reader_matches(&reader, selector, address),
                "{selector} {address}"
            );
        }
    }
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn country_meta_projection_preserves_ipv4_only_and_early_ipv6_leaf() {
    let bytes = meta_projection_fixture(false, &[("1.2.3.0", 24, 0)], &[b"\x42cn"], &[]);
    for bytes in [bytes.as_slice(), META] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geoip.metadb");
        fs::write(&path, bytes).unwrap();
        let selectors = ["cn".into(), "!cn".into()];
        let database = country::CountryDb::load(&path, &selectors).unwrap();
        assert!(database.capacity() < bytes.len());
        let reader = maxminddb::Reader::from_source(bytes).unwrap();
        for address in [
            "1.2.3.4",
            "8.8.8.8",
            "0.0.0.0",
            "::",
            "::102:304",
            "::ffff:102:304",
            "2001:db8::1",
            "8000::1",
        ] {
            let address = address.parse().unwrap();
            for selector in &selectors {
                assert_eq!(
                    database.matches(selector, address),
                    meta_reader_matches(&reader, selector, address),
                    "{selector} {address}"
                );
            }
        }
    }
}

#[test]
fn country_meta_projection_retains_reader_for_invalid_records_or_larger_indexes() {
    // The first record is valid and matches CN; the later structurally valid
    // map is not a country string/array. It must never invert into a match.
    let invalid = meta_projection_fixture(
        false,
        &[("0.0.0.0", 1, 0), ("128.0.0.0", 1, 1)],
        &[b"\x42cn", b"\xe0"],
        &[],
    );
    let many = (0..32)
        .map(|value| format!("code{value}"))
        .chain(["cn".into(), "!cn".into()])
        .collect::<Vec<_>>();
    for (bytes, selectors) in [
        (invalid.as_slice(), vec!["cn".into(), "!cn".into()]),
        (META, many),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geoip.metadb");
        fs::write(&path, bytes).unwrap();
        let database = country::CountryDb::load(&path, &selectors).unwrap();
        assert!(database.capacity() >= bytes.len());
        let reader = maxminddb::Reader::from_source(bytes).unwrap();
        for address in ["1.2.3.4", "128.0.0.1", "8.8.8.8", "2001:db8::1", "8000::1"] {
            let address = address.parse().unwrap();
            for selector in &selectors {
                assert!(database.available(selector));
                assert_eq!(
                    database.matches(selector, address),
                    meta_reader_matches(&reader, selector, address),
                    "{selector} {address}"
                );
            }
        }
    }
}
