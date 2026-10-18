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
