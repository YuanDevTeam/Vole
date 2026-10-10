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
            assert!(collection.matches_ip(ip, snapshot.as_ref()));
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
