//! Provider state transactions using in-memory HTTP streams and temporary files.
use super::*;
use crate::{
    config::Config,
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    session::{DatagramSession, StreamSession},
};
use async_trait::async_trait;
use std::{collections::VecDeque, sync::Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Responses(Mutex<VecDeque<Vec<u8>>>);

#[async_trait]
impl Dispatcher for Responses {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        let response = self
            .0
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted response");
        let (client, mut peer) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0];
            while peer.read_exact(&mut byte).await.is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = peer.write_all(&response).await;
            let _ = peer.shutdown().await;
        });
        Ok(Box::new(client))
    }

    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

fn response(status: u16, header: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} fixture\r\nETag: \"fixture\"\r\n{header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn template() -> Arc<ProviderTemplate> {
    Config::parse_yaml(
        br#"
mixed-port: 1080
proxy-providers:
  remote: {type: http, url: 'http://subscription.invalid/nodes.yaml', path: nodes.yaml}
proxy-groups:
  - {name: choice, type: select, use: [remote]}
"#,
    )
    .unwrap()
    .providers
    .unwrap()
}

async fn fetch(cache: &mut ProviderCache, response: Vec<u8>) -> io::Result<Option<Candidate>> {
    let user_agent = cache.template.request_user_agent();
    cache
        .fetch(
            0,
            Arc::new(Responses(Mutex::new([response].into()))),
            user_agent,
            true,
            crate::security::SecurityContext::new(),
            CancellationToken::new(),
        )
        .await
}

fn commit_valid(cache: &mut ProviderCache, candidate: Candidate) {
    let mut contents = cache.contents.clone();
    contents.insert(cache.entries[0].key.clone(), candidate.content.clone());
    cache.template.materialize(&contents).unwrap();
    cache
        .commit(0, candidate, &CancellationToken::new())
        .unwrap();
}

#[tokio::test]
async fn default_http_cache_paths_isolate_effective_requests_across_restart_and_fetch_failure() {
    for rule in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let configured = |user_agent| {
            let kind = if rule { "rule" } else { "proxy" };
            let behavior = if rule { ", behavior: domain" } else { "" };
            let usage = if rule {
                "rules: ['RULE-SET,first,DIRECT', 'RULE-SET,second,REJECT']"
            } else {
                "proxy-groups: [{name: choice, type: select, use: [first, second]}]"
            };
            Config::parse_yaml(
                format!(
                    "global-ua: {user_agent}\n{kind}-providers:\n  first: {{type: http, url: 'http://subscription.invalid/shared', header: {{Authorization: ['Bearer first']}}{behavior}}}\n  second: {{type: http, url: 'http://subscription.invalid/shared', header: {{Authorization: ['Bearer second']}}{behavior}}}\n{usage}\n"
                )
                .as_bytes(),
            )
            .unwrap()
            .providers
            .unwrap()
        };
        let template = configured("fixture-agent");
        let mut cache = ProviderCache::open(root.path(), template.clone()).unwrap();
        let paths = cache
            .entries
            .iter()
            .map(|entry| entry.path.clone().unwrap())
            .collect::<Vec<_>>();
        let payloads = if rule {
            ["payload: [first.example]", "payload: [second.example]"]
        } else {
            [
                "proxies: [{name: first-node, type: direct}]",
                "proxies: [{name: second-node, type: direct}]",
            ]
        };
        for (index, body) in payloads.iter().enumerate() {
            let candidate = cache
                .fetch(
                    index,
                    Arc::new(Responses(Mutex::new([response(200, "", body)].into()))),
                    template.request_user_agent(),
                    true,
                    crate::security::SecurityContext::new(),
                    CancellationToken::new(),
                )
                .await
                .unwrap()
                .unwrap();
            cache
                .commit(index, candidate, &CancellationToken::new())
                .unwrap();
        }
        template.materialize(&cache.contents).unwrap();
        let expected = cache.contents.clone();
        let mut restored = ProviderCache::open(root.path(), template.clone()).unwrap();
        assert_eq!(restored.contents, expected);
        assert_ne!(paths[0], paths[1]);
        for (index, body) in payloads.iter().enumerate() {
            let entry = &restored.entries[index];
            assert_eq!(entry.path.as_ref(), Some(&paths[index]));
            assert!(entry.state.downloaded);
            assert_eq!(fs::read_to_string(&paths[index]).unwrap(), *body);
            let metadata: Metadata =
                serde_json::from_slice(&fs::read(metadata_path(&paths[index])).unwrap()).unwrap();
            assert_eq!(
                metadata.url,
                source_key(&entry.spec, &template.request_user_agent()).unwrap()
            );
            assert!(
                restored
                    .fetch(
                        index,
                        Arc::new(Responses(Mutex::new([response(503, "", "")].into()))),
                        template.request_user_agent(),
                        true,
                        crate::security::SecurityContext::new(),
                        CancellationToken::new(),
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(restored.contents, expected);
        template.materialize(&restored.contents).unwrap();

        let changed = ProviderCache::open(root.path(), configured("other-agent")).unwrap();
        for (index, entry) in changed.entries.iter().enumerate() {
            assert_ne!(entry.path.as_ref(), Some(&paths[index]));
            assert!(!entry.state.available);
        }
    }
}

#[tokio::test]
async fn file_candidate_keeps_read_mtime_when_source_is_replaced_before_commit() {
    for rules in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("provider.yaml");
        let template = Config::parse_yaml(
            if rules {
                "rule-providers: {remote: {type: file, path: provider.yaml, behavior: domain}}\nrules: ['RULE-SET,remote,DIRECT']\n"
            } else {
                "proxy-providers: {remote: {type: file, path: provider.yaml}}\nproxy-groups: [{name: choice, type: select, use: [remote]}]\n"
            }
            .as_bytes(),
        )
        .unwrap()
        .providers
        .unwrap();
        let write = |file: &Path, count, seconds| {
            let items = (0..count)
                .map(|index| {
                    if rules {
                        format!("domain{index}.example")
                    } else {
                        format!("{{name: node{index}, type: direct}}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            fs::write(
                file,
                format!("{}: [{items}]", if rules { "payload" } else { "proxies" }),
            )
            .unwrap();
            let modified = UNIX_EPOCH + Duration::from_secs(seconds);
            fs::OpenOptions::new()
                .write(true)
                .open(file)
                .unwrap()
                .set_modified(modified)
                .unwrap();
            assert_eq!(fs::metadata(file).unwrap().modified().unwrap(), modified);
            modified
        };
        let initial_time = write(&path, 1, 1000);
        let mut cache = ProviderCache::open(root.path(), template).unwrap();
        assert_eq!(cache.entries[0].modified, Some(initial_time));
        let fetched_time = write(&path, 2, 2000);
        let candidate = fetch(&mut cache, Vec::new()).await.unwrap().unwrap();
        assert_eq!(content_len(&candidate.content), 2);

        // Graph preparation can yield while an editor atomically replaces the file.
        let replacement = root.path().join("replacement.yaml");
        let replacement_time = write(&replacement, 3, 3000);
        fs::rename(&replacement, &path).unwrap();
        commit_valid(&mut cache, candidate);
        assert_eq!(content_len(&cache.contents[&cache.entries[0].key]), 2);
        assert_eq!(cache.entries[0].modified, Some(fetched_time));

        let replacement = fetch(&mut cache, Vec::new())
            .await
            .unwrap()
            .expect("the replacement must remain detectable after the older candidate commits");
        assert_eq!(content_len(&replacement.content), 3);
        commit_valid(&mut cache, replacement);
        assert_eq!(cache.entries[0].modified, Some(replacement_time));
        assert_eq!(content_len(&cache.contents[&cache.entries[0].key]), 3);
        assert!(fetch(&mut cache, Vec::new()).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn uri_provider_candidate_keeps_filters_override_and_authenticated_cache_identity() {
    let root = tempfile::tempdir().unwrap();
    let configured = |password: &str| {
        Config::parse_yaml(
            format!(
                r#"
proxy-providers:
  remote:
    type: http
    url: 'http://subscriber:{password}@subscription.invalid/nodes?token=private'
    path: nodes
    filter: '^edge$'
    override: {{additional-prefix: 'chosen-', interface-name: eth0}}
proxy-groups:
  - {{name: choice, type: select, use: [remote]}}
"#
            )
            .as_bytes(),
        )
        .unwrap()
        .providers
        .unwrap()
    };
    let source = configured("first");
    let mut cache = ProviderCache::open(root.path(), source.clone()).unwrap();
    let uri = "socks5://candidate-user:candidate-password@192.0.2.1:1080#edge\nsocks5://192.0.2.2:1080#other\n";
    let candidate = fetch(
        &mut cache,
        response(200, "Subscription-Userinfo: upload=7\r\n", uri),
    )
    .await
    .unwrap()
    .unwrap();
    let debug = format!("{:?}", candidate.content);
    assert!(!debug.contains("candidate-password"));
    assert!(!debug.contains("192.0.2.1"));
    let mut contents = cache.contents.clone();
    contents.insert(cache.entries[0].key.clone(), candidate.content.clone());
    let config = cache.template.materialize(&contents).unwrap();
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].tag, "chosen-edge");
    commit_valid(&mut cache, candidate);
    let path = root.path().join("nodes");
    let sidecar = metadata_path(&path);
    let old_body = fs::read(&path).unwrap();
    let old_metadata = fs::read(&sidecar).unwrap();
    let visible = String::from_utf8(old_metadata.clone()).unwrap();
    for secret in ["subscriber", "first", "private", "subscription.invalid"] {
        assert!(!visible.contains(secret));
    }
    let mut legacy: serde_json::Value = serde_json::from_slice(&old_metadata).unwrap();
    legacy["url"] = serde_json::json!(http::source_identity(&source.proxies[0].1.url));
    fs::write(&sidecar, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let upgraded = ProviderCache::open(root.path(), source.clone()).unwrap();
    assert!(upgraded.entries[0].state.available);
    assert!(!upgraded.entries[0].state.downloaded);
    assert_eq!(upgraded.entries[0].metadata.etag, None);
    fs::write(&sidecar, &old_metadata).unwrap();
    let mut header_source = source.as_ref().clone();
    header_source.proxies[0]
        .1
        .header
        .insert("Authorization".into(), vec!["Bearer changed".into()]);
    // URL Basic wins over this unused header, so its actual request is unchanged.
    assert!(
        ProviderCache::open(root.path(), Arc::new(header_source))
            .unwrap()
            .entries[0]
            .state
            .downloaded
    );
    let mut cookie_source = source.as_ref().clone();
    cookie_source.proxies[0]
        .1
        .header
        .insert("Cookie".into(), vec!["subscription=different".into()]);
    let cookie_cache = ProviderCache::open(root.path(), Arc::new(cookie_source)).unwrap();
    assert!(cookie_cache.entries[0].state.available);
    assert!(!cookie_cache.entries[0].state.downloaded);
    assert_eq!(cookie_cache.entries[0].metadata.etag, None);
    let mut cache = ProviderCache::open(root.path(), configured("second")).unwrap();
    assert!(cache.entries[0].state.available);
    assert!(!cache.entries[0].state.downloaded);
    assert_eq!(cache.entries[0].metadata.etag, None);
    assert_eq!(cache.entries[0].state.subscription_info, None);
    // A validator from a different credential identity cannot authorize 304.
    assert!(fetch(&mut cache, response(304, "", "")).await.is_err());
    assert_eq!(fs::read(&path).unwrap(), old_body);
    assert_eq!(fs::read(&sidecar).unwrap(), old_metadata);
    assert!(
        fetch(
            &mut cache,
            response(
                200,
                "Subscription-Userinfo: upload=99\r\n",
                "socks5://private-password@invalid"
            )
        )
        .await
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), old_body);
    assert_eq!(fs::read(&sidecar).unwrap(), old_metadata);
    let mut restored = ProviderCache::open(root.path(), source).unwrap();
    assert_eq!(
        restored.entries[0].state.subscription_info.unwrap().upload,
        7
    );
    assert!(
        fetch(
            &mut restored,
            response(304, "Subscription-Userinfo: upload=9\r\n", "")
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        restored.entries[0].state.subscription_info.unwrap().upload,
        9
    );
}

#[test]
fn age_then_base64_uri_provider_uses_the_existing_candidate_parser() {
    use base64::Engine as _;
    use std::io::Write;
    let secret = include_str!("../../tests/fixtures/provider-age/x25519.key").trim();
    let identity = secret.parse::<age::x25519::Identity>().unwrap();
    let encryptor = age::Encryptor::with_recipients(std::iter::once(
        &identity.to_public() as &dyn age::Recipient
    ))
    .unwrap();
    let mut encrypted = Vec::new();
    let armor =
        age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::AsciiArmor)
            .unwrap();
    let mut writer = encryptor.wrap_output(armor).unwrap();
    writer
        .write_all(
            base64::engine::general_purpose::STANDARD
                .encode("socks5://192.0.2.1:1080#edge")
                .as_bytes(),
        )
        .unwrap();
    writer.finish().unwrap().finish().unwrap();
    let mut template = template();
    Arc::make_mut(&mut template).proxies[0].1.age_identities =
        super::super::age_provider::Identities::from_value(serde_yaml_ng::Value::String(
            secret.into(),
        ))
        .unwrap();
    let content = template
        .parse_content(&template.proxies[0].1, &encrypted)
        .unwrap();
    assert!(
        matches!(content,ProviderContent::Proxies(ref proxies) if proxies.len()==1 && proxies[0]["name"].as_str()==Some("edge"))
    );
    let mut contents = ProviderContents::new();
    contents.insert(
        ProviderTemplate::key(false, &template.proxies[0].0),
        content,
    );
    assert_eq!(template.materialize(&contents).unwrap().proxies.len(), 1);
}

#[tokio::test]
async fn bundle_cache_precedes_archive_and_bad_cache_falls_back_before_http() {
    let root = tempfile::tempdir().unwrap();
    let template = Config::parse_yaml(br#"
mixed-port: 1080
rule-providers:
  offline: {type: http, url: 'http://rules.invalid/current.mrs', path: rules.mrs, behavior: ipcidr, format: mrs, path-in-bundle: rules/cn.mrs}
rules: ['RULE-SET,offline,DIRECT']
"#).unwrap().providers.unwrap();
    let member = crate::resource::bundle::tests::mrs();
    let bundle = crate::resource::bundle::tests::archive(&member, true);
    let archive_path = root.path().join("BundleMRS.7z");
    let cache_path = root.path().join("rules.mrs");
    fs::write(&archive_path, &bundle).unwrap();
    fs::write(&cache_path, b"invalid cached MRS").unwrap();
    let mut cache = ProviderCache::open(root.path(), template.clone()).unwrap();
    assert!(cache.entries[0].state.available);
    assert!(!cache.entries[0].state.downloaded);
    assert!(cache.entries[0].metadata.bundled);
    assert_eq!(cache.entries[0].metadata.etag, None);
    assert_eq!(cache.next_due(), Some(0));
    assert_eq!(fs::read(&cache_path).unwrap(), member);
    assert_eq!(cache.entries[0].state.error, None);
    cache.template.materialize(&cache.contents).unwrap();

    // A valid local cache avoids archive parsing and still owes its first real
    // HTTP fetch when the cached bytes were extracted from the bundle.
    fs::write(&archive_path, b"broken archive").unwrap();
    cache = ProviderCache::open(root.path(), template.clone()).unwrap();
    assert!(!cache.entries[0].state.downloaded);
    assert_eq!(cache.next_due(), Some(0));

    // Bad cache and invalid bundled MRS leave the HTTP vehicle available.
    fs::write(&cache_path, b"bad cache").unwrap();
    fs::write(
        &archive_path,
        crate::resource::bundle::tests::archive(b"bad MRS", false),
    )
    .unwrap();
    cache = ProviderCache::open(root.path(), template.clone()).unwrap();
    assert!(!cache.entries[0].state.available);
    assert_eq!(cache.next_due(), Some(0));
    let mut reply = format!(
        "HTTP/1.1 200 fixture\r\nETag: \"remote\"\r\nContent-Length: {}\r\n\r\n",
        member.len()
    )
    .into_bytes();
    reply.extend_from_slice(&member);
    let candidate = fetch(&mut cache, reply).await.unwrap().unwrap();
    commit_valid(&mut cache, candidate);
    assert!(cache.entries[0].state.downloaded);
    assert!(!cache.entries[0].metadata.bundled);
    assert_eq!(
        cache.entries[0].metadata.etag.as_deref(),
        Some("\"remote\"")
    );
    assert_eq!(cache.next_refresh(), None);
    let cache = ProviderCache::open(root.path(), template).unwrap();
    assert!(cache.entries[0].state.downloaded);
    assert!(!cache.entries[0].metadata.bundled);
}

#[tokio::test(start_paused = true)]
async fn refresh_deadline_preserves_fetch_completion_phase_and_zero_disables_polling() {
    let root = tempfile::tempdir().unwrap();
    let mut cache = ProviderCache::open(root.path(), template()).unwrap();
    cache.entries[0].spec.interval = 1;
    let started = tokio::time::Instant::now();
    let candidate = fetch(
        &mut cache,
        response(
            200,
            "",
            "proxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080}]",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    // Publication completes just after a fixed one-second poll boundary.
    tokio::time::advance(Duration::from_millis(20)).await;
    commit_valid(&mut cache, candidate);
    let deadline = started + Duration::from_millis(1020);
    assert_eq!(cache.next_refresh(), Some((0, deadline)));
    tokio::time::advance(Duration::from_millis(980)).await;
    assert_eq!(cache.next_due(), None);
    tokio::time::sleep_until(cache.next_refresh().unwrap().1).await;
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert_eq!(cache.next_due(), Some(0));
    assert!(
        fetch(&mut cache, response(304, "", ""))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        cache.next_refresh(),
        Some((0, deadline + Duration::from_secs(1)))
    );
    cache.entries[0].spec.interval = 0;
    assert_eq!(cache.next_refresh(), None);
    assert_eq!(cache.next_due(), None);
}

#[tokio::test(start_paused = true)]
async fn refresh_deadline_selects_oldest_due_provider_and_keeps_failure_backoff() {
    let root = tempfile::tempdir().unwrap();
    let template = Config::parse_yaml(
        br#"
mixed-port: 1080
proxy-providers:
  a: {type: http, url: 'http://subscription.invalid/a', interval: 1}
  b: {type: http, url: 'http://subscription.invalid/b', interval: 1}
proxy-groups:
  - {name: choice, type: select, use: [a, b]}
"#,
    )
    .unwrap()
    .providers
    .unwrap();
    let mut cache = ProviderCache::open(root.path(), template).unwrap();
    let started = tokio::time::Instant::now();
    cache.entries[0].next = started + Duration::from_secs(2);
    cache.entries[1].next = started + Duration::from_secs(1);
    assert_eq!(
        cache.next_refresh(),
        Some((1, started + Duration::from_secs(1)))
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(cache.next_due(), Some(1));
    cache.reject(1);
    assert_eq!(cache.next_due(), Some(0));
    cache.entries[0].state.downloaded = true;
    cache.entries[0].spec.interval = 0;
    assert_eq!(cache.next_due(), None);
    assert_eq!(
        cache.next_refresh(),
        Some((1, started + Duration::from_secs(12)))
    );
    cache.entries[1].spec.kind = ProviderType::Inline;
    assert_eq!(cache.next_refresh(), None);
}

#[tokio::test]
async fn subscription_metadata_follows_successful_candidates_304_and_verified_disk_cache() {
    let root = tempfile::tempdir().unwrap();
    let template = template();
    let mut cache = ProviderCache::open(root.path(), template.clone()).unwrap();
    assert!(
        serde_json::to_value(&cache.entries[0].state)
            .unwrap()
            .get("subscriptionInfo")
            .is_none()
    );
    let old = "proxies: [{name: old, type: socks5, server: 192.0.2.1, port: 1080}]";
    let new = "proxies: [{name: new, type: socks5, server: 192.0.2.2, port: 1080}]";
    let info = |upload| SubscriptionInfo {
        upload,
        ..Default::default()
    };
    let candidate = fetch(
        &mut cache,
        response(200, "Subscription-Userinfo: upload=1\r\n", old),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(cache.entries[0].state.subscription_info, None);
    commit_valid(&mut cache, candidate);
    assert_eq!(cache.entries[0].state.subscription_info, Some(info(1)));
    assert_eq!(
        serde_json::to_value(&cache.entries[0].state).unwrap()["subscriptionInfo"],
        serde_json::json!({"Upload":1,"Download":0,"Total":0,"Expire":0})
    );

    let previous_content = cache.contents[&cache.entries[0].key].clone();
    assert!(
        fetch(
            &mut cache,
            response(304, "Subscription-Userinfo: upload=2\r\n", "")
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(cache.entries[0].state.subscription_info, Some(info(2)));
    assert_eq!(
        fs::read_to_string(root.path().join("nodes.yaml")).unwrap(),
        old
    );
    assert_eq!(content_len(&previous_content), cache.entries[0].state.count);
    let restored = ProviderCache::open(root.path(), template.clone()).unwrap();
    assert_eq!(restored.entries[0].state.subscription_info, Some(info(2)));

    assert!(
        fetch(&mut cache, response(304, "", ""))
            .await
            .unwrap()
            .is_none()
    );
    let candidate = fetch(&mut cache, response(200, "", new))
        .await
        .unwrap()
        .unwrap();
    commit_valid(&mut cache, candidate);
    assert_eq!(cache.entries[0].state.subscription_info, Some(info(2)));
    let saved_metadata = fs::read(metadata_path(&root.path().join("nodes.yaml"))).unwrap();

    let candidate = fetch(
        &mut cache,
        response(200, "Subscription-Userinfo: upload=77\r\n", old),
    )
    .await
    .unwrap()
    .unwrap();
    fs::remove_file(candidate.temporary.as_ref().unwrap()).unwrap();
    assert!(
        cache
            .commit(0, candidate, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(
        fs::read(metadata_path(&root.path().join("nodes.yaml"))).unwrap(),
        saved_metadata
    );
    assert_eq!(
        fs::read_to_string(root.path().join("nodes.yaml")).unwrap(),
        new
    );
    assert!(
        fetch(
            &mut cache,
            response(500, "Subscription-Userinfo: upload=66\r\n", "")
        )
        .await
        .is_err()
    );

    assert!(
        fetch(
            &mut cache,
            response(
                200,
                "Subscription-Userinfo: upload=99\r\n",
                "not a provider"
            )
        )
        .await
        .is_err()
    );
    let candidate = fetch(&mut cache, response(200, "Subscription-Userinfo: upload=88\r\n", "proxies: [{name: cycle, type: socks5, server: 192.0.2.1, port: 1080, dialer-proxy: cycle}]")).await.unwrap().unwrap();
    let mut proposed = cache.contents.clone();
    proposed.insert(cache.entries[0].key.clone(), candidate.content.clone());
    assert!(template.materialize(&proposed).is_err());
    cache.reject(0);
    drop(candidate);
    assert_eq!(cache.entries[0].state.subscription_info, Some(info(2)));
    assert_eq!(
        fs::read(metadata_path(&root.path().join("nodes.yaml"))).unwrap(),
        saved_metadata
    );
    assert_eq!(
        fs::read_to_string(root.path().join("nodes.yaml")).unwrap(),
        new
    );
    assert_eq!(
        ProviderCache::open(root.path(), template.clone())
            .unwrap()
            .entries[0]
            .state
            .subscription_info,
        Some(info(2))
    );

    // A valid file with a stale sidecar is usable, but its subscription data is untrusted.
    fs::write(root.path().join("nodes.yaml"), old).unwrap();
    let restored = ProviderCache::open(root.path(), template.clone()).unwrap();
    assert!(restored.entries[0].state.available);
    assert_eq!(restored.entries[0].state.subscription_info, None);

    fs::write(root.path().join("nodes.yaml"), new).unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&saved_metadata).unwrap();
    legacy.as_object_mut().unwrap().remove("subscription_info");
    fs::write(
        metadata_path(&root.path().join("nodes.yaml")),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    let legacy = ProviderCache::open(root.path(), template).unwrap();
    assert!(legacy.entries[0].state.available);
    assert_eq!(legacy.entries[0].state.subscription_info, None);
}

#[tokio::test]
async fn failed_304_sidecar_write_does_not_publish_subscription_metadata() {
    let root = tempfile::tempdir().unwrap();
    let mut cache = ProviderCache::open(root.path(), template()).unwrap();
    let body = "proxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080}]";
    let candidate = fetch(
        &mut cache,
        response(200, "Subscription-Userinfo: upload=1\r\n", body),
    )
    .await
    .unwrap()
    .unwrap();
    commit_valid(&mut cache, candidate);
    let path = metadata_path(&root.path().join("nodes.yaml"));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        fetch(
            &mut cache,
            response(304, "Subscription-Userinfo: upload=99\r\n", "")
        )
        .await
        .is_err()
    );
    assert_eq!(
        cache.entries[0].metadata.subscription_info.unwrap().upload,
        1
    );
    assert_eq!(cache.entries[0].state.subscription_info.unwrap().upload, 1);
    let candidate = fetch(
        &mut cache,
        response(
            200,
            "Subscription-Userinfo: upload=88\r\n",
            "proxies: [{name: replacement, type: socks5, server: 192.0.2.2, port: 1080}]",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        cache
            .commit(0, candidate, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(cache.entries[0].state.subscription_info.unwrap().upload, 1);
    assert_eq!(
        fs::read_to_string(root.path().join("nodes.yaml")).unwrap(),
        body
    );
}

#[tokio::test]
async fn age_provider_cache_and_file_refresh_preserve_candidate_contract() {
    let root = tempfile::tempdir().unwrap();
    let mut template = template();
    Arc::make_mut(&mut template).proxies[0].1.age_identities =
        super::super::age_provider::Identities::from_value(serde_yaml_ng::Value::String(
            include_str!("../../tests/fixtures/provider-age/x25519.key").into(),
        ))
        .unwrap();
    let ciphertext = include_str!("../../tests/fixtures/provider-age/x25519.age");
    let mut cache = ProviderCache::open(root.path(), template.clone()).unwrap();
    let candidate = fetch(&mut cache, response(200, "", ciphertext))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        candidate.metadata.hash,
        hex(&Sha256::digest(ciphertext.as_bytes()))
    );
    commit_valid(&mut cache, candidate);
    let old = cache.contents.clone();
    let cache_path = cache.entries[0].path.as_ref().unwrap().clone();
    assert_eq!(fs::read(&cache_path).unwrap(), ciphertext.as_bytes());
    let recovered = ProviderCache::open(root.path(), template).unwrap();
    assert_eq!(recovered.contents, old);
    assert_eq!(
        recovered.entries[0].metadata.etag.as_deref(),
        Some("\"fixture\"")
    );
    let wrong_recipient = include_str!("../../tests/fixtures/provider-age/hybrid.age");
    assert!(
        fetch(&mut cache, response(200, "", wrong_recipient))
            .await
            .is_err()
    );
    assert_eq!(cache.contents, old);
    assert_eq!(fs::read(&cache_path).unwrap(), ciphertext.as_bytes());
    assert!(cache.entries[0].state.available);
    assert_eq!(
        cache.entries[0].metadata.etag.as_deref(),
        Some("\"fixture\"")
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let stopped =
        ProviderCache::open_with_cancel(root.path(), cache.template.clone(), Some(&cancellation));
    assert_eq!(stopped.err().unwrap().kind(), io::ErrorKind::Interrupted);
    let mut file_template = cache.template.as_ref().clone();
    file_template.proxies[0].1.kind = ProviderType::File;
    file_template.proxies[0].1.url.clear();
    let mut file_cache = ProviderCache::open(root.path(), Arc::new(file_template)).unwrap();
    assert_eq!(file_cache.contents, old);
    file_cache.entries[0].modified = None;
    let candidate = fetch(&mut file_cache, Vec::new()).await.unwrap().unwrap();
    commit_valid(&mut file_cache, candidate);
    assert_eq!(file_cache.contents, old);
    fs::write(&cache_path, wrong_recipient).unwrap();
    file_cache.entries[0].modified = None;
    assert!(fetch(&mut file_cache, Vec::new()).await.is_err());
    assert_eq!(file_cache.contents, old);
    assert!(file_cache.entries[0].state.available);
}

#[test]
fn configuration_candidate_reads_bundle_without_persisting_body_or_metadata() {
    let root = tempfile::tempdir().unwrap();
    let configured=Config::parse_yaml(br#"
rule-providers:
  offline: {type: http, url: 'http://rules.invalid/current.mrs', path: nested/rules.mrs, behavior: ipcidr, format: mrs, path-in-bundle: rules/cn.mrs}
rules: ['RULE-SET,offline,DIRECT', 'MATCH,DIRECT']
"#).unwrap().providers.unwrap();
    let archive =
        crate::resource::bundle::tests::archive(&crate::resource::bundle::tests::mrs(), true);
    fs::write(root.path().join("BundleMRS.7z"), archive).unwrap();
    let cache =
        ProviderCache::open_candidate(root.path(), configured.clone(), &CancellationToken::new())
            .unwrap();
    assert!(cache.entries[0].state.available);
    assert!(!root.path().join("nested").exists());
    assert!(cache.template.materialize(&cache.contents).is_ok());
    cache
        .prepare_paths(root.path(), &CancellationToken::new())
        .unwrap();
    assert!(root.path().join("nested").is_dir());
    assert!(!root.path().join("nested/rules.mrs").exists());
    fs::write(
        root.path().join("nested/rules.mrs"),
        b"invalid existing body",
    )
    .unwrap();
    let metadata = metadata_path(&root.path().join("nested/rules.mrs"));
    fs::write(&metadata, b"existing sidecar").unwrap();
    let second =
        ProviderCache::open_candidate(root.path(), configured, &CancellationToken::new()).unwrap();
    assert!(second.entries[0].state.available);
    assert_eq!(
        fs::read(root.path().join("nested/rules.mrs")).unwrap(),
        b"invalid existing body"
    );
    assert_eq!(fs::read(metadata).unwrap(), b"existing sidecar");
}

#[test]
fn provider_metadata_requires_bounded_regular_files() {
    let root = tempfile::tempdir().unwrap();
    let body = root.path().join("nodes.yaml");
    fs::write(&body, b"proxies: [{name: cached, type: direct}]").unwrap();
    let sidecar = metadata_path(&body);
    fs::File::create(&sidecar)
        .unwrap()
        .set_len(MAX_METADATA_BYTES + 1)
        .unwrap();
    let control = super::super::age_provider::DecodeControl::new(
        None,
        std::time::Instant::now() + http::DEFAULT_DOWNLOAD_TIMEOUT,
    );
    assert!(read_bounded(&sidecar, MAX_METADATA_BYTES, &control).is_err());
    let cache = ProviderCache::open(root.path(), template()).unwrap();
    assert!(cache.entries[0].state.available);
    assert!(!cache.entries[0].state.downloaded);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        fs::remove_file(&sidecar).unwrap();
        let name = std::ffi::CString::new(sidecar.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let cache = ProviderCache::open(root.path(), template()).unwrap();
        assert!(cache.entries[0].state.available);
        assert!(!cache.entries[0].state.downloaded);
    }
}

#[test]
fn authorized_provider_roots_read_file_sources_and_write_only_http_caches() {
    use crate::resource::paths::ProviderPaths;
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let shared = root.path().join("shared");
    fs::create_dir(&data).unwrap();
    fs::create_dir(&shared).unwrap();
    let source = shared.join("source.yaml");
    let cache_path = shared.join("http/nodes.yaml");
    let source_bytes = b"proxies: [{name: from-file, type: direct}]";
    fs::write(&source, source_bytes).unwrap();
    let document = serde_json::json!({"proxy-providers":{
        "file":{"type":"file","path":source.to_str().unwrap()},
        "http":{"type":"http","url":"https://fixture.invalid/nodes","path":cache_path.to_str().unwrap()}
    },"rules":["MATCH,DIRECT"]}).to_string();
    let mut template = crate::config::Config::parse_yaml(document.as_bytes())
        .unwrap()
        .providers
        .unwrap();
    assert!(ProviderCache::open(&data, template.clone()).is_err());
    let paths =
        ProviderPaths::from_os_value(Some(std::env::join_paths([&shared]).unwrap()), root.path())
            .unwrap();
    Arc::make_mut(&mut template).resource_paths = Arc::new(paths);
    let mut cache = ProviderCache::open(&data, template.clone()).unwrap();
    assert!(cache.contents.contains_key("proxies/file"));
    cache
        .prepare_paths(&data, &CancellationToken::new())
        .unwrap();
    assert_eq!(fs::read(&source).unwrap(), source_bytes);
    assert!(!metadata_path(&source).exists());
    let body = b"proxies: [{name: from-http, type: direct}]";
    let temporary = cache_path.parent().unwrap().join("owned-download.tmp");
    fs::write(&temporary, body).unwrap();
    let index = cache
        .entries
        .iter()
        .position(|entry| entry.state.name == "http")
        .unwrap();
    let content = template
        .parse_content(&cache.entries[index].spec, body)
        .unwrap();
    cache
        .commit(
            index,
            Candidate {
                content,
                temporary: Some(temporary),
                modified: None,
                metadata: Metadata {
                    url: source_key(&cache.entries[index].spec, &template.request_user_agent())
                        .unwrap(),
                    hash: hex(&Sha256::digest(body)),
                    ..Metadata::default()
                },
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(fs::read(&cache_path).unwrap(), body);
    assert!(metadata_path(&cache_path).is_file());
    assert_eq!(fs::read(&source).unwrap(), source_bytes);
}
