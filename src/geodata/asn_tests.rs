use std::{fs, sync::Arc};

use super::*;
use crate::{
    config::{Config, Network, RuleAction},
    routing::{RoutingContext, RuleEvaluation, RuleSet},
    session::Destination,
};

pub(super) const FIXTURE: &[u8] =
    include_bytes!("../../tests/fixtures/geodata/GeoLite2-ASN-Test.mmdb");

fn rule(kind: RuleKind) -> RuleSpec {
    RuleSpec {
        kind,
        action: RuleAction::Reject,
        no_resolve: false,
    }
}

#[test]
fn asn_official_fixture_direct_lookup_and_absent_asset() {
    let dir = tempfile::tempdir().unwrap();
    assert!(GeoData::load(dir.path(), &[]).unwrap().is_empty());
    fs::write(dir.path().join(ASN_FILE_NAME), FIXTURE).unwrap();
    let rules = [rule(RuleKind::IpAsn("15169".into()))];
    let data = GeoData::load(dir.path(), &rules).unwrap();
    assert_eq!(data.allocation_capacity(), FIXTURE.len());
    assert!(data.matches_asn("15169", "1.0.0.1".parse().unwrap()));
    assert!(data.matches_asn("6730", "2001:1700::1".parse().unwrap()));
    assert!(data.matches_asn("0", "192.0.2.1".parse().unwrap()));
    for payload in ["AS15169", "015169", "+15169", "0"] {
        assert!(!data.matches_asn(payload, "1.0.0.1".parse().unwrap()));
    }
    assert!(!GeoData::EMPTY.matches_asn("0", "192.0.2.1".parse().unwrap()));
    assert!(!GeoData::load(dir.path(), &[]).unwrap().asn_available());
}

#[test]
fn asn_schema_visitors_and_lazy_resolution_use_actual_context() {
    let mut empty = Config::parse_yaml(b"mixed-port: 1080\nrules: ['IP-ASN,,DIRECT']\n").unwrap();
    assert_eq!(empty.rules[0].kind, RuleKind::IpAsn(String::new()));
    RuleSet::compile(empty.take_runtime_rules()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(ASN_FILE_NAME), FIXTURE).unwrap();
    let mut config = Config::parse_yaml(
        br#"
mixed-port: 1080
geox-url: {asn: https://assets.example.test/ASN.mmdb}
rule-providers:
  local: {type: inline, behavior: classical, payload: ["IP-ASN,AS15169", "SRC-IP-ASN,6730"]}
sub-rules:
  nested: ["OR,((IP-ASN,0015169),(SRC-IP-ASN,6730)),DIRECT"]
rules:
  - IP-ASN,15169,REJECT,no-resolve
  - IP-ASN,15169,REJECT
  - IP-ASN,6730,DIRECT,src,no-resolve
  - SRC-IP-ASN,6730,DIRECT
  - RULE-SET,local,DIRECT
"#,
    )
    .unwrap();
    let requirements = GeoRequirements::for_config(&config).unwrap();
    assert!(requirements.requires(GeoDataKind::Asn));
    assert!(requirements.codes(GeoDataKind::Asn).next().is_none());
    assert_eq!(config.rules[2], config.rules[3]);
    assert_eq!(
        config.geodata_update.as_ref().unwrap().urls.asn,
        "https://assets.example.test/ASN.mmdb"
    );
    let data = GeoData::load(dir.path(), &config.rules).unwrap();
    let mut runtime_config = config.clone();
    let rules = RuleSet::compile(runtime_config.take_runtime_rules()).unwrap();
    let mut context = RoutingContext::new(
        Network::Tcp,
        &Destination::domain("example.test", 443).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        rules.evaluate_with_geo(&context, &data),
        RuleEvaluation::NeedsIpResolution { rule_index: 1 }
    ));
    assert!(matches!(
        rules.evaluate_with_geo(&context, &GeoData::EMPTY),
        RuleEvaluation::Matched(result) if result.action == RuleAction::Direct
    ));
    let source_rule = rule(RuleKind::SrcIpAsn("6730".into()));
    assert_eq!(
        crate::routing::matches_rule(&source_rule, &context, &data),
        Ok(false)
    );
    context.set_source("[2001:1700::1]:49152".parse().unwrap());
    assert_eq!(
        crate::routing::matches_rule(&source_rule, &context, &data),
        Ok(true)
    );
    let literal = RoutingContext::new(
        Network::Tcp,
        &Destination::Ip("1.0.0.1:443".parse().unwrap()),
    )
    .unwrap();
    assert_eq!(
        crate::routing::matches_rule(&rule(RuleKind::IpAsn("15169".into())), &literal, &data),
        Ok(true)
    );
    // Definition and classical content are independently traversed even when
    // the main list has no direct ASN predicate.
    config.rules = vec![rule(RuleKind::Match)];
    assert!(
        GeoRequirements::for_config(&config)
            .unwrap()
            .requires(GeoDataKind::Asn)
    );
    let collection = crate::config::RuleCollection::from_payload(
        vec!["IP-ASN,15169".into()],
        crate::config::providers::RuleBehavior::Classical,
    )
    .unwrap();
    assert!(
        collection
            .matches_ip("1.0.0.1".parse().unwrap(), &data, &Default::default())
            .unwrap()
    );
    let nested = rule(RuleKind::Not(Box::new(rule(RuleKind::RuleSet {
        name: "local".into(),
        content: Some(Arc::new(collection)),
        source: false,
    }))));
    assert!(
        GeoRequirements::collect(&[nested], &[])
            .unwrap()
            .requires(GeoDataKind::Asn)
    );
}
