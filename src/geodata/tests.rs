use std::{fs, net::IpAddr};

use tempfile::tempdir;

use super::*;
use crate::{
    config::{DnsNameserverPolicy, RuleAction, RuleKind, RuleSpec},
    routing::normalize_domain_name,
};

fn varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

fn field_varint(field: u32, value: u64) -> Vec<u8> {
    let mut output = varint(u64::from(field) << 3);
    output.extend(varint(value));
    output
}

fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
    let mut output = varint((u64::from(field) << 3) | 2);
    output.extend(varint(value.len() as u64));
    output.extend(value);
    output
}

fn domain(domain_type: u64, value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    if domain_type != 0 {
        output.extend(field_varint(1, domain_type));
    }
    output.extend(field_bytes(2, value.as_bytes()));
    output
}

fn attributed_domain(domain_type: u64, value: &str, attributes: &[(&str, u32, u64)]) -> Vec<u8> {
    let mut record = domain(domain_type, value);
    for (key, field, value) in attributes {
        let mut attribute = field_bytes(1, key.as_bytes());
        attribute.extend(field_varint(*field, *value));
        record.extend(field_bytes(3, &attribute));
    }
    record
}

fn site(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
    let mut output = field_bytes(1, code.as_bytes());
    for domain in domains {
        output.extend(field_bytes(2, domain));
    }
    output
}

fn site_list(sites: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    for site in sites {
        output.extend(field_bytes(1, site));
    }
    output
}

fn cidr(ip: &[u8], prefix: u64) -> Vec<u8> {
    let mut output = field_bytes(1, ip);
    if prefix != 0 {
        output.extend(field_varint(2, prefix));
    }
    output
}

fn geoip(code: &str, cidrs: &[Vec<u8>], reverse: bool) -> Vec<u8> {
    let mut output = field_bytes(1, code.as_bytes());
    for cidr in cidrs {
        output.extend(field_bytes(2, cidr));
    }
    if reverse {
        output.extend(field_varint(3, 1));
    }
    output
}

fn geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    for entry in entries {
        output.extend(field_bytes(1, entry));
    }
    output
}

fn rule(kind: RuleKind) -> RuleSpec {
    RuleSpec {
        kind,
        action: RuleAction::Route(crate::config::RouteTargetId::Proxy(
            crate::config::ProxyId::new(0).unwrap(),
        )),
        no_resolve: false,
    }
}

fn dns_policy(codes: &[&str]) -> DnsNameserverPolicy {
    DnsNameserverPolicy {
        selector: crate::config::DnsPolicySelector::GeoSite(
            codes
                .iter()
                .map(|code| (*code).to_owned())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        nameservers: Vec::new().into_boxed_slice(),
    }
}

fn write_asset(dir: &Path, name: &str, contents: &[u8]) {
    fs::write(dir.join(name), contents).unwrap();
}

#[test]
fn empty_rules_do_not_open_assets() {
    let dir = tempdir().unwrap();
    let data = GeoData::load(dir.path(), &[]).unwrap();
    assert!(data.is_empty());
    assert_eq!(data.allocation_capacity(), 0);
    assert_eq!(data.peak_allocation_capacity(), 0);
}

#[test]
fn selector_normalization_deduplicates_and_folds_unicode_attributes() {
    assert_eq!(
        normalize_selector(GeoDataKind::GeoSite, "!CN@ ads @@CN@Ads").unwrap(),
        "!cn@ads@cn"
    );
    for (left, right) in [("Σ", "ς"), ("σ", "ς"), ("ſ", "S"), ("K", "K"), ("µ", "Μ")] {
        assert_eq!(
            normalize_selector(GeoDataKind::GeoSite, &format!("cn@{left}")).unwrap(),
            normalize_selector(GeoDataKind::GeoSite, &format!("cn@{right}")).unwrap(),
            "{left} / {right}",
        );
    }
    assert_eq!(
        normalize_selector(GeoDataKind::GeoSite, "cn@İ").unwrap(),
        normalize_selector(GeoDataKind::GeoSite, "cn@i").unwrap(),
    );
    assert_ne!(fold_attribute("İ"), fold_attribute("i"));
    assert_eq!(
        normalize_selector(GeoDataKind::GeoIp, "!CN").unwrap(),
        "!cn"
    );
    assert_eq!(
        normalize_selector(GeoDataKind::GeoSite, "GOOGLE@!CN").unwrap(),
        "google@!cn"
    );
    for (kind, selector) in [
        (GeoDataKind::GeoIp, "cn@ads"),
        (GeoDataKind::GeoSite, "!"),
        (GeoDataKind::GeoSite, "!!cn"),
        (GeoDataKind::GeoSite, "cn@a b"),
        (GeoDataKind::GeoSite, "cn@a\u{0}b"),
    ] {
        assert!(normalize_selector(kind, selector).is_err(), "{selector:?}");
    }
}

#[test]
fn attribute_intersection_inversion_and_all_pattern_kinds_share_one_base() {
    let dir = tempdir().unwrap();
    let both = [("ADS", 2, 0), ("cn", 3, 0)];
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                attributed_domain(0, "keyword", &both),
                attributed_domain(1, "^regex[0-9]+\\.example$", &both),
                attributed_domain(2, "domain.example", &both),
                attributed_domain(3, "full.example", &both),
                attributed_domain(3, "ads-only.example", &[("ads", 2, 1)]),
                attributed_domain(3, "plain.example", &[]),
            ],
        )]),
    );
    let rules = [
        rule(RuleKind::GeoSite("CN@ADS@CN".into())),
        rule(RuleKind::GeoSite("!cn@cn@ads".into())),
        rule(RuleKind::GeoSite("cn".into())),
        rule(RuleKind::GeoSite("!cn".into())),
        rule(RuleKind::GeoSite("cn@missing".into())),
        rule(RuleKind::GeoSite("!cn@missing".into())),
    ];
    let data = GeoData::load(dir.path(), &rules).unwrap();
    assert_eq!(data.sites.len(), 1);
    assert_eq!(data.sites[0].patterns.len(), 5);
    assert_eq!(data.sites[0].regexes.len(), 1);
    assert_eq!(data.sites[0].filters.len(), 2);
    let filter = data.sites[0]
        .filters
        .iter()
        .find(|filter| filter.attributes == "ads@cn")
        .unwrap();
    assert_eq!(filter.patterns.len(), 3);
    assert_eq!(filter.regex_indices, [0]);
    for name in [
        "keyword.example",
        "regex42.example",
        "domain.example",
        "sub.domain.example",
        "full.example",
    ] {
        assert!(data.matches_geosite("cn@ads@cn", name), "{name}");
        assert!(!data.matches_geosite("!cn@ads@cn", name), "{name}");
    }
    for name in ["ads-only.example", "plain.example", "absent.example"] {
        assert!(!data.matches_geosite("cn@ads@cn", name), "{name}");
        assert!(data.matches_geosite("!cn@ads@cn", name), "{name}");
    }
    assert!(!data.matches_geosite("!cn", ""));
    assert!(!data.matches_geosite("!cn@missing", ""));
    assert!(data.geosite_available("cn@missing"));
    assert!(!data.matches_geosite("cn@missing", "any.example"));
    assert!(data.matches_geosite("!cn@missing", "any.example"));
    assert!(!data.geosite_available("cn@not-requested"));
    assert!(!data.matches_geosite("!absent", "any.example"));
}

#[test]
fn attribute_filtered_load_skips_unselected_invalid_regex_and_shares_record_union() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                attributed_domain(1, "(?=unsupported)", &[("other", 2, 1)]),
                attributed_domain(3, "both.example", &[("a", 2, 0), ("b", 3, 0)]),
                attributed_domain(3, "a.example", &[("a", 2, 1)]),
                attributed_domain(3, "b.example", &[("b", 2, 1)]),
            ],
        )]),
    );
    let rules = [
        rule(RuleKind::GeoSite("cn@a".into())),
        rule(RuleKind::GeoSite("!cn@a".into())),
        rule(RuleKind::GeoSite("CN@A@A".into())),
        rule(RuleKind::GeoSite("cn@b".into())),
    ];
    let data = GeoData::load(dir.path(), &rules).unwrap();
    assert_eq!(data.sites.len(), 1);
    assert_eq!(data.sites[0].patterns.len(), 3);
    assert_eq!(data.sites[0].filters.len(), 2);
    assert_eq!(data.sites[0].selectors.len(), 3);
    assert!(data.matches_geosite("cn@a", "both.example"));
    assert!(data.matches_geosite("cn@b", "both.example"));
    assert!(data.matches_geosite("cn@a", "a.example"));
    assert!(!data.matches_geosite("cn@b", "a.example"));
    assert!(data.matches_geosite("cn@b", "b.example"));
    assert!(data.matches_geosite("!cn@a", "b.example"));
}

#[test]
fn dns_selectors_share_attributes_with_business_rules_and_reload() {
    let dir = tempdir().unwrap();
    let key = "Σ";
    let selector = normalize_selector(GeoDataKind::GeoSite, "cn@ς").unwrap();
    let inverted = format!("!{selector}");
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                attributed_domain(3, "old.example", &[(key, 2, 0)]),
                attributed_domain(3, "unselected.example", &[]),
            ],
        )]),
    );
    let rules = [rule(RuleKind::GeoSite(selector.clone()))];
    let policies = [dns_policy(&[&inverted, &selector])];
    let requirements = GeoRequirements::collect(&rules, &policies).unwrap();
    assert_eq!(requirements.total_codes(), 2);
    assert_eq!(requirements.sites.values.len(), 1);
    let manager = GeoDataManager::open(dir.path(), std::time::Duration::from_secs(60)).unwrap();
    let registration = manager.register(requirements).unwrap();
    let matcher = registration.matcher();
    assert!(matcher.matches_geosite(&selector, "old.example"));
    assert!(matcher.matches_geosite(&inverted, "unselected.example"));
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[attributed_domain(3, "new.example", &[("σ", 3, 0)])],
        )]),
    );
    assert!(manager.reload().geosite_available);
    assert!(!matcher.matches_geosite(&selector, "old.example"));
    assert!(matcher.matches_geosite(&selector, "new.example"));
    assert!(!matcher.matches_geosite(&inverted, "new.example"));
}

#[test]
fn literal_bang_attribute_is_not_an_attribute_complement() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "google",
            &[
                attributed_domain(3, "tagged.example", &[("!cn", 2, 0)]),
                attributed_domain(3, "cn.example", &[("cn", 3, 0)]),
                attributed_domain(3, "untagged.example", &[]),
            ],
        )]),
    );
    let rules = [
        rule(RuleKind::GeoSite("google@!cn".into())),
        rule(RuleKind::GeoSite("!google@!cn".into())),
    ];
    let data = GeoData::load(dir.path(), &rules).unwrap();
    assert_eq!(data.sites[0].filters.len(), 1);
    assert!(data.sites[0].filters[0].all_records);
    assert!(data.sites[0].filters[0].patterns.is_empty());
    assert!(data.sites[0].filters[0].regex_indices.is_empty());
    assert!(data.matches_geosite("google@!cn", "tagged.example"));
    for name in ["cn.example", "untagged.example"] {
        assert!(!data.matches_geosite("google@!cn", name));
        assert!(data.matches_geosite("!google@!cn", name));
    }
    assert!(!data.matches_geosite("!google@!cn", "tagged.example"));
}

#[test]
fn selector_lowercase_and_attribute_key_simple_fold_follow_mihomo_order() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                attributed_domain(3, "ascii-i.example", &[("i", 2, 0)]),
                attributed_domain(3, "dotted-i.example", &[("İ", 2, 0)]),
            ],
        )]),
    );
    let selector = normalize_selector(GeoDataKind::GeoSite, "cn@İ").unwrap();
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite(selector.clone()))]).unwrap();
    assert!(data.matches_geosite(&selector, "ascii-i.example"));
    assert!(!data.matches_geosite(&selector, "dotted-i.example"));
}

#[test]
fn missing_inverted_category_is_unavailable_but_empty_filter_is_available() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("cn", &[attributed_domain(3, "untagged.example", &[])])]),
    );
    let manager = GeoDataManager::open(dir.path(), std::time::Duration::from_secs(60)).unwrap();
    let registration = manager
        .register(
            GeoRequirements::collect(&[rule(RuleKind::GeoSite("!missing".into()))], &[]).unwrap(),
        )
        .unwrap();
    let matcher = registration.matcher();
    assert!(!registration.initial_report().geosite.available);
    assert!(!matcher.geosite_available("!missing"));
    assert!(!matcher.matches_geosite("!missing", "any.example"));
    drop(registration);
    let registration = manager
        .register(
            GeoRequirements::collect(&[rule(RuleKind::GeoSite("!cn@missing".into()))], &[])
                .unwrap(),
        )
        .unwrap();
    let matcher = registration.matcher();
    assert!(registration.initial_report().geosite.available);
    assert!(matcher.geosite_available("!cn@missing"));
    assert!(matcher.matches_geosite("!cn@missing", "any.example"));
}

#[test]
fn inverted_ip_aliases_share_one_cidr_matcher_and_keep_all_sites() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("cn", &[cidr(&[10, 0, 0, 0], 8)], true)]),
    );
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                attributed_domain(3, "kept.example", &[("ads", 2, 0)]),
                attributed_domain(3, "last.example", &[("ads", 2, 1)]),
            ],
        )]),
    );
    let rules = [
        rule(RuleKind::GeoIp("!CN".into())),
        rule(RuleKind::GeoIp("cn".into())),
        rule(RuleKind::GeoSite("cn@ads".into())),
    ];
    let data = GeoData::load(dir.path(), &rules).unwrap();
    assert_eq!(data.ips.len(), 1);
    assert_eq!(data.ips[0].v4.len(), 1);
    assert!(data.matches_geoip("!cn", "2001:db8::1".parse().unwrap()));
    assert!(!data.matches_geoip("!cn", "10.2.3.4".parse().unwrap()));
    assert!(data.matches_geosite("cn@ads", "kept.example"));
    assert!(data.matches_geosite("cn@ads", "last.example"));
}

#[test]
fn category_lookup_preserves_independent_codes_through_load_and_reload() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[
            site("Az", &[domain(3, "az.example")]),
            site("AA", &[domain(3, "aa.example")]),
            site("Z", &[domain(3, "z.example")]),
            site("a-b", &[domain(3, "hyphen.example")]),
            site("a", &[domain(3, "a.example")]),
        ]),
    );
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[
            geoip("a-B", &[cidr(&[10, 4, 0, 0], 16)], false),
            geoip("z", &[cidr(&[10, 5, 0, 0], 16)], false),
            geoip("a", &[cidr(&[10, 1, 0, 0], 16)], false),
            geoip("AZ", &[cidr(&[10, 3, 0, 0], 16)], false),
            geoip("aa", &[cidr(&[10, 2, 0, 0], 16)], false),
        ]),
    );
    let rules: Vec<_> = ["z", "a-b", "a", "az", "aa"]
        .into_iter()
        .flat_map(|code| {
            [
                rule(RuleKind::GeoSite(code.to_owned())),
                rule(RuleKind::GeoIp(code.to_owned())),
            ]
        })
        .collect();
    let data = GeoData::load(dir.path(), &rules).unwrap();
    let manager = GeoDataManager::open(dir.path(), std::time::Duration::from_secs(60)).unwrap();
    let registration = manager
        .register(GeoRequirements::collect(&rules, &[]).unwrap())
        .unwrap();
    assert!(registration.initial_report().geosite.available);
    assert!(registration.initial_report().geoip.available);
    let matcher = registration.matcher();
    for loaded in [&data as &dyn GeoMatcher, matcher.as_ref()] {
        for (code, domain, address) in [
            ("A", "a.example", "10.1.0.1"),
            ("aA", "aa.example", "10.2.0.1"),
            ("AZ", "az.example", "10.3.0.1"),
            ("A-b", "hyphen.example", "10.4.0.1"),
            ("z", "z.example", "10.5.0.1"),
        ] {
            assert!(loaded.geosite_available(code), "{code}");
            assert!(loaded.geoip_available(code), "{code}");
            assert!(loaded.matches_geosite(code, domain), "{code}");
            assert!(
                loaded.matches_geoip(code, address.parse().unwrap()),
                "{code}"
            );
            assert!(!loaded.matches_geosite(code, "absent.example"), "{code}");
            assert!(
                !loaded.matches_geoip(code, "192.0.2.1".parse().unwrap()),
                "{code}"
            );
        }
        for code in ["", "0", "a-", "a-bb", "aaa", "ay", "zz", "a?", " a"] {
            assert!(!loaded.geosite_available(code), "{code}");
            assert!(!loaded.geoip_available(code), "{code}");
            assert!(!loaded.matches_geosite(code, "a.example"), "{code}");
            assert!(
                !loaded.matches_geoip(code, "10.1.0.1".parse().unwrap()),
                "{code}"
            );
        }
    }

    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[
            site("a", &[domain(3, "new-a.example")]),
            site("a-b", &[domain(3, "new-hyphen.example")]),
            site("z", &[domain(3, "new-z.example")]),
            site("aa", &[domain(3, "new-aa.example")]),
            site("az", &[domain(3, "new-az.example")]),
        ]),
    );
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[
            geoip("aa", &[cidr(&[172, 2, 0, 0], 16)], false),
            geoip("az", &[cidr(&[172, 3, 0, 0], 16)], false),
            geoip("a", &[cidr(&[172, 1, 0, 0], 16)], false),
            geoip("z", &[cidr(&[172, 5, 0, 0], 16)], false),
            geoip("a-b", &[cidr(&[172, 4, 0, 0], 16)], false),
        ]),
    );
    let report = manager.reload();
    assert!(report.geosite_available);
    assert!(report.geoip_available);
    for (code, old_domain, new_domain, old_address, new_address) in [
        ("A", "a.example", "new-a.example", "10.1.0.1", "172.1.0.1"),
        (
            "aA",
            "aa.example",
            "new-aa.example",
            "10.2.0.1",
            "172.2.0.1",
        ),
        (
            "AZ",
            "az.example",
            "new-az.example",
            "10.3.0.1",
            "172.3.0.1",
        ),
        (
            "A-b",
            "hyphen.example",
            "new-hyphen.example",
            "10.4.0.1",
            "172.4.0.1",
        ),
        ("z", "z.example", "new-z.example", "10.5.0.1", "172.5.0.1"),
    ] {
        assert!(!matcher.matches_geosite(code, old_domain), "{code}");
        assert!(matcher.matches_geosite(code, new_domain), "{code}");
        assert!(
            !matcher.matches_geoip(code, old_address.parse().unwrap()),
            "{code}"
        );
        assert!(
            matcher.matches_geoip(code, new_address.parse().unwrap()),
            "{code}"
        );
    }
}

#[test]
fn geosite_loads_beyond_former_value_and_memory_quotas() {
    let dir = tempdir().unwrap();
    let mut selected = field_bytes(1, b"cn");
    // Exceeds the former 2 MiB values and 8 MiB ledger budgets; selected
    // records are not truncated on any platform.
    for index in 0..131_073 {
        selected.extend(field_bytes(
            2,
            &domain(
                2,
                &format!("long-domain-that-crosses-the-old-byte-budget-{index:x}.example.test"),
            ),
        ));
    }
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[selected]));
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".to_owned()))]).unwrap();
    for index in [0, 65_536, 131_071, 131_072] {
        let value = format!("long-domain-that-crosses-the-old-byte-budget-{index:x}.example.test");
        assert!(data.matches_geosite("cn", &value));
        assert!(data.matches_geosite("cn", &format!("sub.{value}")));
        assert!(!data.matches_geosite("cn", &format!("not{value}")));
    }
    assert!(data.allocation_capacity() > 8 * 1024 * 1024);
    assert!(data.peak_allocation_capacity() >= data.allocation_capacity());
    drop(data);

    // Runtime preparation uses the manager's independently loaded snapshot.
    let manager = GeoDataManager::open(
        dir.path().join("managed"),
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    fs::copy(
        dir.path().join(GEOSITE_FILE_NAME),
        manager.store_dir().join(GEOSITE_FILE_NAME),
    )
    .unwrap();
    let registration = manager
        .register(GeoRequirements::collect(&[rule(RuleKind::GeoSite("cn".into()))], &[]).unwrap())
        .unwrap();
    assert!(registration.initial_report().geosite.available);
    assert!(registration.initial_report().allocation_capacity > 8 * 1024 * 1024);
    assert!(registration.matcher().matches_geosite(
        "cn",
        "long-domain-that-crosses-the-old-byte-budget-20000.example.test"
    ));
}

#[test]
fn allocation_ledger_observes_growth_without_admission_limits() {
    let mut ledger = AllocationLedger::default();
    let mut bytes = Vec::<u8>::new();
    ensure_vec_capacity(&mut bytes, 8, &mut ledger).unwrap();
    bytes.extend_from_slice(b"12345678");
    ensure_vec_capacity(&mut bytes, 1, &mut ledger).unwrap();
    assert_eq!(ledger.used, 16);
    assert_eq!(ledger.peak, 24);
    assert_eq!(bytes, b"12345678");
    assert!(ensure_vec_capacity(&mut bytes, usize::MAX, &mut ledger).is_err());
    assert_eq!(ledger.used, 16);
}

#[test]
fn nameserver_policy_alone_loads_geosite_and_shares_rule_categories() {
    let dir = tempdir().unwrap();
    let fixture = site_list(&[
        site("private", &[domain(2, "internal.example")]),
        site("cn", &[domain(2, "example.cn")]),
    ]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);

    let policy = dns_policy(&["private", "cn"]);
    let data =
        GeoData::load_with_dns_policies(dir.path(), &[], std::slice::from_ref(&policy)).unwrap();
    assert!(data.matches_geosite("private", "host.internal.example"));
    assert!(data.matches_geosite("cn", "www.example.cn"));
    assert_eq!(data.sites.len(), 2);

    let data = GeoData::load_with_dns_policies(
        dir.path(),
        &[rule(RuleKind::GeoSite("private".to_owned()))],
        &[policy],
    )
    .unwrap();
    assert_eq!(data.sites.len(), 2);
}

#[test]
fn nameserver_policy_missing_category_still_fails_closed() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("private", &[])]),
    );
    let error =
        GeoData::load_with_dns_policies(dir.path(), &[], &[dns_policy(&["missing"])]).unwrap_err();
    assert!(matches!(
        error,
        GeoDataError::MissingCode {
            kind: GeoDataKind::GeoSite,
            ..
        }
    ));
}

#[test]
fn references_and_asset_categories_grow_without_fixed_count_limits() {
    let dir = tempdir().unwrap();
    let sites: Vec<_> = (0..4097)
        .map(|index| {
            site(
                &format!("code{index}"),
                &[domain(3, &format!("site{index}.test"))],
            )
        })
        .collect();
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&sites));
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("cn", &[cidr(&[10, 0, 0, 0], 8)], false)]),
    );
    let codes: Vec<_> = (0..17)
        .map(|index| format!("code{index}"))
        .chain(["code4096".to_owned()])
        .collect();
    let policy = dns_policy(&codes.iter().map(String::as_str).collect::<Vec<_>>());
    let rules = [
        rule(RuleKind::GeoIp("cn".into())),
        rule(RuleKind::GeoSite("CODE0".into())),
    ];
    let requirements = GeoRequirements::collect(&rules, std::slice::from_ref(&policy)).unwrap();
    assert_eq!(requirements.total_codes(), 19);
    let data = GeoData::load_with_dns_policies(dir.path(), &rules, &[policy]).unwrap();
    for index in (0..17).chain([4096]) {
        assert!(data.matches_geosite(&format!("code{index}"), &format!("site{index}.test")));
    }
    assert!(data.matches_geoip("cn", "10.1.2.3".parse().unwrap()));
}

#[test]
fn geosite_supports_all_domain_types_and_attributes() {
    let dir = tempdir().unwrap();

    let mut attributed = domain(2, "Example.COM.");
    let mut attribute = field_bytes(1, b"ads");
    attribute.extend(field_varint(2, 1));
    attributed.extend(field_bytes(3, &attribute));

    let fixture = site_list(&[site(
        "TeSt",
        &[
            domain(0, "Needle"),
            attributed,
            domain(3, "full.example"),
            domain(1, r"^r[0-9]+\.example$"),
            domain(1, r"other\.test"),
        ],
    )]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);

    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("test".to_owned()))]).unwrap();
    assert!(data.matches_geosite("TEST", "has-needle.example"));
    assert!(data.matches_geosite("test", "example.com"));
    assert!(data.matches_geosite("test", "a.example.com"));
    assert!(data.matches_geosite("test", "full.example"));
    assert!(!data.matches_geosite("test", "a.full.example"));
    assert!(data.matches_geosite("test", "r42.example"));
    assert!(!data.matches_geosite("test", "R42.example"));
    assert!(data.matches_geosite("test", "prefix.other.test.example"));
    assert!(!data.matches_geosite("missing", "example.com"));
}

#[test]
fn geosite_normalizes_unicode_domain_values() {
    let dir = tempdir().unwrap();
    let fixture = site_list(&[site("idna", &[domain(2, "例子.测试")])]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("IDNA".to_owned()))]).unwrap();
    let normalized = normalize_domain_name("子.例子.测试").unwrap();
    assert!(data.matches_geosite("idna", &normalized));
}

#[test]
fn geosite_literal_patterns_do_not_require_dns_hostname_syntax() {
    let dir = tempdir().unwrap();
    let long_label = format!("{}.test", "x".repeat(64));
    let records = [
        domain(2, "EXAMPLE.TEST"),
        domain(2, "\"QUOTED.TEST"),
        domain(2, "FOO_BAR.TEST"),
        domain(3, "FULL_VALUE.TEST"),
        domain(2, "-EDGE-.TEST"),
        domain(2, "PERCENT%VALUE.TEST"),
        domain(2, "BACK\\SLASH.TEST"),
        domain(2, &long_label),
        domain(2, "*.LITERAL.TEST"),
    ];
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("compat", &records)]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("compat".into()))]).unwrap();
    assert!(data.geosite_available("compat"));
    assert_eq!(data.sites[0].patterns.len(), records.len());
    for value in [
        "example.test",
        "sub.example.test",
        "\"quoted.test",
        "sub.\"quoted.test",
        "foo_bar.test",
        "sub.foo_bar.test",
        "full_value.test",
        "-edge-.test",
        "percent%value.test",
        "back\\slash.test",
        long_label.as_str(),
        "*.literal.test",
    ] {
        assert!(data.matches_geosite("compat", value), "{value}");
    }
    for value in [
        "quoted.test",
        "notfoo_bar.test",
        "sub.full_value.test",
        "host.literal.test",
        "absent.test",
    ] {
        assert!(!data.matches_geosite("compat", value), "{value}");
    }
}

#[test]
fn geosite_preserves_utf8_patterns_when_idna_is_not_applicable() {
    let dir = tempdir().unwrap();
    // A joiner without a valid IDNA context is still a static literal pattern.
    let value = "\u{200d}.EXAMPLE";
    assert!(idna::domain_to_ascii(value).is_err());
    // Successful IDNA conversion can also erase an ignored-only value.
    assert_eq!(idna::domain_to_ascii("\u{ad}").unwrap(), "");
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("opaque", &[domain(2, value), domain(3, "\u{ad}")])]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("opaque".into()))]).unwrap();
    assert!(data.matches_geosite("opaque", "\u{200d}.example"));
    assert!(data.matches_geosite("opaque", "\u{ad}"));
    assert!(!data.matches_geosite("opaque", ""));
    assert!(!data.matches_geosite("opaque", "example"));
}

#[test]
fn geosite_pattern_compatibility_does_not_accept_invalid_records() {
    let dir = tempdir().unwrap();
    for record in [
        domain(2, ""),
        domain(3, ""),
        field_varint(1, 2),
        [field_varint(1, 2), field_bytes(2, &[0xff])].concat(),
        domain(4, "example.test"),
    ] {
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site("invalid", &[record])]),
        );
        assert!(matches!(
            GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("invalid".into()))]),
            Err(GeoDataError::InvalidDomain { .. })
        ));
    }
}

#[test]
fn geosite_membership_preserves_overlapping_unsorted_record_types() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site(
            "cn",
            &[
                domain(3, "z.example"),
                domain(2, "shared.example"),
                domain(0, "needle"),
                domain(3, "shared.example"),
                domain(2, "a.example"),
                domain(3, "only.example"),
                domain(2, "shared.example"),
                domain(1, "^r[0-9]+\\.test$"),
            ],
        )]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".into()))]).unwrap();
    for value in [
        "z.example",
        "shared.example",
        "sub.shared.example",
        "a.example",
        "deep.sub.a.example",
        "only.example",
        "has-needle.test",
        "r12.test",
    ] {
        assert!(data.matches_geosite("cn", value), "{value}");
    }
    for value in [
        "sub.z.example",
        "sub.only.example",
        "notshared.example",
        "shared.example.test",
        "not-a.example",
        "absent.test",
    ] {
        assert!(!data.matches_geosite("cn", value), "{value}");
    }
}

#[test]
fn geoip_matches_v4_v6_and_compacts_siblings() {
    let dir = tempdir().unwrap();
    let fixture = geoip_list(&[geoip(
        "private",
        &[
            cidr(&[10, 0, 0, 1], 9),
            cidr(&[10, 128, 0, 1], 9),
            cidr(&[10, 12, 0, 0], 16),
            cidr(
                &u128::from_be_bytes([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                    .to_be_bytes(),
                7,
            ),
        ],
        false,
    )]);
    write_asset(dir.path(), GEOIP_FILE_NAME, &fixture);
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("PRIVATE".to_owned()))]).unwrap();

    assert_eq!(data.ips[0].v4.len(), 1);
    assert!(data.matches_geoip("private", "10.255.4.1".parse().unwrap()));
    assert!(!data.matches_geoip("private", "11.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("private", "fd00::1".parse().unwrap()));
    assert!(!data.matches_geoip("private", "2001:db8::1".parse().unwrap()));
}

#[test]
fn unselected_category_payload_is_not_decoded() {
    let dir = tempdir().unwrap();
    let mut unselected = field_bytes(1, b"unused");
    unselected.extend(field_bytes(2, &[0xff]));
    let fixture = site_list(&[unselected, site("selected", &[domain(3, "ok.example")])]);
    write_asset(dir.path(), GEOSITE_FILE_NAME, &fixture);

    let data = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("selected".to_owned()))],
    )
    .unwrap();
    assert!(data.matches_geosite("selected", "ok.example"));
}

#[test]
fn selected_corrupt_payload_fails_closed() {
    let dir = tempdir().unwrap();
    let mut selected = field_bytes(1, b"selected");
    selected.extend(field_bytes(2, &[0xff]));
    write_asset(dir.path(), GEOSITE_FILE_NAME, &site_list(&[selected]));

    let error = GeoData::load(
        dir.path(),
        &[rule(RuleKind::GeoSite("selected".to_owned()))],
    )
    .unwrap_err();
    assert!(matches!(error, GeoDataError::Malformed { .. }));
}

#[test]
fn duplicate_codes_are_ascii_case_insensitive() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("CN", &[]), site("cn", &[])]),
    );
    let error = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::DuplicateCode { .. }));
}

#[test]
fn missing_code_and_invalid_regex_are_errors() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("other", &[])]),
    );
    let error =
        GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("missing".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::MissingCode { .. }));

    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("broken", &[domain(1, "(?=lookaround)")])]),
    );
    let error =
        GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("broken".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::InvalidRegex { .. }));

    for unsupported in ["(?u:\\w+)", "(?x:example)", "例子"] {
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site("unsupported", &[domain(1, unsupported)])]),
        );
        let error = GeoData::load(
            dir.path(),
            &[rule(RuleKind::GeoSite("unsupported".to_owned()))],
        )
        .unwrap_err();
        assert!(matches!(error, GeoDataError::InvalidRegex { .. }));
    }
}

#[test]
fn dat_reverse_match_is_ignored_and_invalid_cidr_is_rejected() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("reverse", &[cidr(&[10, 0, 0, 0], 8)], true)]),
    );
    let data = GeoData::load(
        dir.path(),
        &[
            rule(RuleKind::GeoIp("reverse".to_owned())),
            rule(RuleKind::GeoIp("!reverse".to_owned())),
        ],
    )
    .unwrap();
    assert!(data.matches_geoip("reverse", "10.1.2.3".parse().unwrap()));
    assert!(!data.matches_geoip("reverse", "192.0.2.1".parse().unwrap()));
    assert!(!data.matches_geoip("!reverse", "10.1.2.3".parse().unwrap()));
    assert!(data.matches_geoip("!reverse", "192.0.2.1".parse().unwrap()));

    write_asset(
        dir.path(),
        GEOIP_FILE_NAME,
        &geoip_list(&[geoip("bad", &[cidr(&[10, 0, 0, 0], 33)], false)]),
    );
    let error = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("bad".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::InvalidCidr { .. }));
}

#[test]
fn geosite_regexes_load_without_vole_record_or_cumulative_source_quotas() {
    let dir = tempdir().unwrap();
    let records: Vec<_> = (0..513)
        .map(|index| domain(1, &format!("^{}r{index}\\.test$", "a".repeat(130))))
        .collect();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("regex", &records)]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("regex".into()))]).unwrap();
    for index in [0, 512] {
        assert!(data.matches_geosite("regex", &format!("{}r{index}.test", "a".repeat(130))));
    }
    assert!(!data.matches_geosite("regex", "no-match.test"));
    // Only the owned vector capacity is visible to this diagnostic ledger;
    // the library's compiled programs and search caches are intentionally not.
    assert!(data.allocation_capacity() >= records.len() * mem::size_of::<Regex>());
}

#[test]
fn geosite_byte_regex_preserves_search_classes_and_supported_flags() {
    let dir = tempdir().unwrap();
    for (pattern, matched, not_matched) in [
        (r"^a.b$", "a-b", "a\nb"),
        (r"^[^.]+\.test$", "abc.test", "a.b.test"),
        (r"^\w+\.test$", "abc_42.test", "a-b.test"),
        (r"^\w+\.test$", "abc.test", "é.test"),
        (r"needle", "has-needle.example", "absent.example"),
        (r"(?i:FLAG)", "flag.example", "quiet.example"),
        (r"(?m:^line$)", "first\nline\nlast", "first\nnot-line\nlast"),
        (r"(?s:^a.b$)", "a\nb", "ab"),
        (r"(?U:a.+b)", "prefix-a---b-suffix", "prefix-a-suffix"),
    ] {
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site("byte-regex", &[domain(1, pattern)])]),
        );
        let data =
            GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("byte-regex".into()))]).unwrap();
        assert!(data.matches_geosite("byte-regex", matched), "{pattern}");
        assert!(
            !data.matches_geosite("byte-regex", not_matched),
            "{pattern}"
        );
    }
}

#[test]
fn geosite_byte_regex_loads_short_pattern_with_exponential_complete_dfa() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("binary", &[domain(1, r"[01]*1[01]{20}")])]),
    );
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("binary".into()))]).unwrap();
    assert!(data.matches_geosite("binary", &format!("1{}", "0".repeat(20))));
    assert!(!data.matches_geosite("binary", &format!("1{}", "0".repeat(19))));
    assert!(!data.matches_geosite("binary", &"0".repeat(21)));
}

#[test]
fn geosite_byte_regex_library_rejections_do_not_expose_expression_source() {
    let dir = tempdir().unwrap();
    for (pattern, expected_detail) in [
        ("private-expression([", "invalid regex syntax"),
        (
            "private-expression(?:ab){1000000}",
            "compiled regex exceeds the library default size limit",
        ),
    ] {
        write_asset(
            dir.path(),
            GEOSITE_FILE_NAME,
            &site_list(&[site("rejected", &[domain(1, pattern)])]),
        );
        let error =
            GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("rejected".into()))]).unwrap_err();
        let GeoDataError::InvalidRegex { ref detail, .. } = error else {
            panic!("unexpected error kind");
        };
        assert_eq!(detail, expected_detail);
        for formatted in [error.to_string(), format!("{error:?}")] {
            assert!(!formatted.contains(pattern));
            assert!(!formatted.contains("private-expression"));
        }
    }
}

#[test]
fn rejected_byte_regex_reload_skips_the_unavailable_kind() {
    let dir = tempdir().unwrap();
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("regex", &[domain(1, r"^kept\.example$")])]),
    );
    let manager = GeoDataManager::open(dir.path(), std::time::Duration::from_secs(60)).unwrap();
    let registration = manager
        .register(
            GeoRequirements::collect(&[rule(RuleKind::GeoSite("regex".into()))], &[]).unwrap(),
        )
        .unwrap();
    let matcher = registration.matcher();
    assert!(matcher.matches_geosite("regex", "kept.example"));
    write_asset(
        dir.path(),
        GEOSITE_FILE_NAME,
        &site_list(&[site("regex", &[domain(1, "private-expression([")])]),
    );
    assert!(!manager.reload().geosite_available);
    assert!(!matcher.geosite_available("regex"));
    assert!(!matcher.matches_geosite("regex", "kept.example"));
    assert!(!matcher.matches_geosite("regex", "new.example"));
}

#[test]
fn geoip_records_load_without_count_limits_before_cidr_compaction() {
    let dir = tempdir().unwrap();
    let mut category = field_bytes(1, b"cn");
    for _ in 0..320_000 {
        category.extend(field_bytes(2, &cidr(&[10, 0, 0, 1], 32)));
    }
    category.extend(field_bytes(2, &cidr(&[203, 0, 113, 9], 32)));
    write_asset(dir.path(), GEOIP_FILE_NAME, &geoip_list(&[category]));
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("cn".into()))]).unwrap();
    assert!(data.matches_geoip("cn", "10.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("cn", "203.0.113.9".parse().unwrap()));
    assert!(!data.matches_geoip("cn", "203.0.113.10".parse().unwrap()));
}

#[test]
fn large_assets_skip_unselected_payloads_without_file_size_quotas() {
    use std::io::Write;
    let dir = tempdir().unwrap();
    for kind in [GeoDataKind::GeoSite, GeoDataKind::GeoIp] {
        // A valid unselected category with a sparse length-delimited unknown
        // field beyond both former file limits. No giant heap fixture needed.
        let padding = 33 * 1024 * 1024;
        let mut category = field_bytes(1, b"unused");
        category.extend(varint((100 << 3) | 2));
        category.extend(varint(padding));
        let mut file = File::create(dir.path().join(kind.file_name())).unwrap();
        file.write_all(&varint((1 << 3) | 2)).unwrap();
        file.write_all(&varint(category.len() as u64 + padding))
            .unwrap();
        file.write_all(&category).unwrap();
        file.seek(SeekFrom::Current(padding as i64)).unwrap();
        let (selected, rule_kind) = match kind {
            GeoDataKind::GeoSite => (
                site("selected", &[domain(3, "last.test")]),
                RuleKind::GeoSite("selected".into()),
            ),
            GeoDataKind::GeoIp => (
                geoip("selected", &[cidr(&[10, 0, 0, 1], 32)], false),
                RuleKind::GeoIp("selected".into()),
            ),
        };
        file.write_all(&field_bytes(1, &selected)).unwrap();
        let data = GeoData::load(dir.path(), &[rule(rule_kind)]).unwrap();
        match kind {
            GeoDataKind::GeoSite => assert!(data.matches_geosite("selected", "last.test")),
            GeoDataKind::GeoIp => {
                assert!(data.matches_geoip("selected", "10.0.0.1".parse().unwrap()))
            }
        }
    }
}

#[test]
fn malformed_outer_framing_is_rejected() {
    let dir = tempdir().unwrap();
    write_asset(dir.path(), GEOSITE_FILE_NAME, &[0x0a, 0x05, 0x0a]);
    let error = GeoData::load(dir.path(), &[rule(RuleKind::GeoSite("cn".to_owned()))]).unwrap_err();
    assert!(matches!(error, GeoDataError::Malformed { .. }));
}

#[test]
fn matcher_is_send_and_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<GeoData>();
}

#[test]
fn literal_ip_family_does_not_cross_match() {
    let dir = tempdir().unwrap();
    let fixture = geoip_list(&[geoip("v4", &[cidr(&[0, 0, 0, 0], 0)], false)]);
    write_asset(dir.path(), GEOIP_FILE_NAME, &fixture);
    let data = GeoData::load(dir.path(), &[rule(RuleKind::GeoIp("v4".to_owned()))]).unwrap();
    assert!(data.matches_geoip("v4", IpAddr::from([203, 0, 113, 1])));
    assert!(!data.matches_geoip("v4", "::ffff:203.0.113.1".parse().unwrap()));
}

/// Opt-in compatibility check for the real Xray GeoData assets shipped by the
/// app. CI does not require those external files; run with
/// `VOLE_GEODATA_DIR=/path/to/assets/dat cargo test real_xray_geodata -- --ignored --nocapture`.
#[test]
#[ignore = "requires VOLE_GEODATA_DIR containing real geosite.dat and geoip.dat"]
fn real_xray_geodata_loads_common_codes_without_memory_quotas() {
    let dir = std::env::var_os("VOLE_GEODATA_DIR")
        .map(PathBuf::from)
        .expect("VOLE_GEODATA_DIR must point to the directory containing both .dat files");
    let rules = [
        rule(RuleKind::GeoSite("cn".to_owned())),
        rule(RuleKind::GeoSite("geolocation-!cn".to_owned())),
        rule(RuleKind::GeoIp("cn".to_owned())),
        rule(RuleKind::GeoIp("private".to_owned())),
    ];
    let baseline = GeoData::load(
        &dir,
        &[rules[0].clone(), rules[2].clone(), rules[3].clone()],
    )
    .unwrap();
    eprintln!(
        "real GeoData baseline allocation without GEOLOCATION-!CN: retained={} bytes, accounted_peak={} bytes",
        baseline.allocation_capacity(),
        baseline.peak_allocation_capacity(),
    );
    assert!(baseline.matches_geosite("cn", "baidu.com"));
    assert!(baseline.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    assert!(baseline.matches_geoip("cn", "1.0.1.1".parse().unwrap()));
    drop(baseline);

    let documented = GeoData::load(
        &dir,
        &[
            rule(RuleKind::GeoSite("category-ads-all".to_owned())),
            rules[0].clone(),
            rules[2].clone(),
            rules[3].clone(),
        ],
    )
    .unwrap_or_else(|error| panic!("documented GeoData combination failed: {error}"));
    eprintln!(
        "documented GeoData allocation: retained={} bytes, accounted_peak={} bytes",
        documented.allocation_capacity(),
        documented.peak_allocation_capacity(),
    );
    assert!(documented.matches_geosite("cn", "baidu.com"));
    assert!(documented.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    drop(documented);

    let policy = dns_policy(&["private", "cn", "apple"]);
    let policy_data =
        GeoData::load_with_dns_policies(&dir, &[rules[2].clone(), rules[3].clone()], &[policy])
            .unwrap_or_else(|error| panic!("Simple Profile DNS policy GeoData failed: {error}"));
    assert!(policy_data.matches_geosite("private", "localhost"));
    assert!(policy_data.matches_geosite("cn", "baidu.com"));
    assert!(policy_data.matches_geosite("apple", "apple.com"));
    drop(policy_data);

    let data = GeoData::load(&dir, &rules)
        .unwrap_or_else(|error| panic!("real GeoData compatibility failed: {error}"));

    eprintln!(
        "real GeoData allocation: retained={} bytes, accounted_peak={} bytes",
        data.allocation_capacity(),
        data.peak_allocation_capacity(),
    );
    assert!(data.matches_geosite("cn", "baidu.com"));
    assert!(data.matches_geosite("geolocation-!cn", "google.com"));
    assert!(data.matches_geoip("private", "10.0.0.1".parse().unwrap()));
    assert!(data.matches_geoip("cn", "1.0.1.1".parse().unwrap()));
}
