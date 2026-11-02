//! Resource transactions use in-memory HTTP streams, never host listeners.
use super::*;
use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    http_processing::config::PolicyCandidate,
    session::{DatagramSession, StreamSession},
};
use async_trait::async_trait;
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Responses {
    responses: Mutex<VecDeque<Vec<u8>>>,
    calls: AtomicUsize,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl Responses {
    fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: AtomicUsize::new(0),
            requests: Arc::new(Mutex::new(Vec::new())),
        })
    }
}
#[async_trait]
impl Dispatcher for Responses {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(DispatchError::NotAllowed)?;
        let requests = self.requests.clone();
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
            requests.lock().unwrap().push(request);
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
fn response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} fixture\r\nETag: \"fixture\"\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn document(authorization: &str) -> Arc<Document> {
    Document::parse(&format!("rewrite-providers:\n  remote:\n    type: http\n    url: http://rules.example.test/rules.yaml\n    path: remote.yaml\n    header: {{Authorization: ['{authorization}']}}\nrewrite: {{enabled: true, rules: [{{rule-set: remote}}]}}\n")).unwrap()
}
fn document_with_cache(path: &Path) -> Arc<Document> {
    let quoted = serde_yaml_ng::to_string(&path.to_string_lossy().as_ref()).unwrap();
    Document::parse(&format!(
        "rewrite-providers:\n  remote:\n    type: http\n    url: http://rules.example.test/rules.yaml\n    path: {}\nrewrite: {{enabled: true, rules: [{{rule-set: remote}}]}}\n",
        quoted.trim_end()
    ))
    .unwrap()
}
fn network(dispatcher: Arc<Responses>) -> DownloadContext {
    DownloadContext {
        dispatcher,
        security: SecurityContext::new(),
    }
}

#[tokio::test]
async fn http_cache_body_and_metadata_cannot_overwrite_foreground_inputs() {
    for private in [false, true] {
        for metadata in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let body = directory
                .path()
                .join(if private { "ca.pem" } else { "config.yaml" });
            let input = if metadata {
                cache::metadata_path(&body)
            } else {
                body.clone()
            };
            std::fs::write(&input, b"original foreground input").unwrap();
            let mut paths = ProviderPaths::default();
            paths.reserve_inputs([(input.clone(), private)]);
            let context = SourceContext {
                data_dir: Some(directory.path().into()),
                resource_paths: Arc::new(paths),
                ..Default::default()
            };
            let dispatcher = Responses::new([response(200, "payload: []")]);
            let network = network(dispatcher.clone());
            let document = document_with_cache(&body);
            let mut store = Store::new();
            let error = store
                .prepare(
                    document.clone(),
                    &context,
                    Some(&network),
                    &CancellationToken::new(),
                    false,
                )
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 0);
            assert_eq!(std::fs::read(&input).unwrap(), b"original foreground input");
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
            assert!(store.prepared(&document, &context).unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn http_file_resources_keep_public_reads_but_reject_private_inputs() {
    for private in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.yaml");
        std::fs::write(&input, b"payload: []").unwrap();
        let mut paths = ProviderPaths::default();
        paths.reserve_inputs([(input.clone(), private)]);
        let context = SourceContext {
            base_dir: Some(directory.path().into()),
            resource_paths: Arc::new(paths),
            ..Default::default()
        };
        let document = Document::parse("rewrite-providers: {local: {type: file, path: input.yaml}}\nrewrite: {enabled: true, rules: [{rule-set: local}]}\n").unwrap();
        let mut store = Store::new();
        let result = store
            .prepare(document, &context, None, &CancellationToken::new(), false)
            .await;
        if private {
            assert_eq!(
                result.err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
        } else {
            assert!(result.is_ok());
        }
        assert_eq!(std::fs::read(&input).unwrap(), b"payload: []");
    }
}

#[tokio::test]
async fn absolute_http_cache_paths_work_without_borrowing_another_input_context() {
    let directory = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let input = directory.path().join("config.yaml");
    std::fs::write(&input, b"original foreground input").unwrap();
    let mut paths = ProviderPaths::default();
    paths.reserve_inputs([(input.clone(), false)]);
    let context = SourceContext {
        data_dir: Some(directory.path().into()),
        resource_paths: Arc::new(paths),
        ..Default::default()
    };
    let body = external.path().join("remote.yaml");
    let document = document_with_cache(&body);
    let dispatcher = Responses::new([response(200, "payload: []")]);
    let network = network(dispatcher.clone());
    let mut store = Store::new();
    let candidate = store
        .prepare(
            document.clone(),
            &context,
            Some(&network),
            &CancellationToken::new(),
            false,
        )
        .await
        .unwrap();
    assert!(body.is_file());
    assert!(cache::metadata_path(&body).is_file());
    assert!(store.prepared(&document, &context).unwrap().is_some());

    let mut changed = context.clone();
    let mut paths = ProviderPaths::default();
    paths.reserve_inputs([(body.clone(), false)]);
    changed.resource_paths = Arc::new(paths);
    // The location stays the same for live-update compatibility. Its protected
    // inputs still distinguish prepared candidates and snapshot adoption.
    assert_eq!(context.identity(), changed.identity());
    assert!(store.prepared(&document, &changed).unwrap().is_none());
    assert!(Store::new().adopt(candidate, &changed).is_err());
    changed = context.clone();
    changed.config_path = Some(input.clone());
    assert!(store.prepared(&document, &changed).unwrap().is_none());

    let mut refresh = SourceContext {
        data_dir: context.data_dir.clone(),
        ..Default::default()
    };
    store.inherit_inputs(&mut refresh);
    let error = store
        .prepare(
            document_with_cache(&input),
            &refresh,
            Some(&network),
            &CancellationToken::new(),
            true,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 1);
    assert_eq!(std::fs::read(&input).unwrap(), b"original foreground input");
}

#[cfg(unix)]
#[tokio::test]
async fn periodic_http_refresh_rechecks_reserved_input_aliases_before_download() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("config.yaml");
    std::fs::write(&input, b"original foreground input").unwrap();
    let mut paths = ProviderPaths::default();
    paths.reserve_inputs([(input.clone(), false)]);
    let context = SourceContext {
        data_dir: Some(directory.path().into()),
        resource_paths: Arc::new(paths),
        ..Default::default()
    };
    let body = directory.path().join("remote.yaml");
    let dispatcher = Responses::new([response(200, "payload: []")]);
    let network = network(dispatcher.clone());
    let mut store = Store::new();
    store
        .prepare(
            document_with_cache(&body),
            &context,
            Some(&network),
            &CancellationToken::new(),
            false,
        )
        .await
        .unwrap();
    std::fs::remove_file(&body).unwrap();
    symlink(&input, &body).unwrap();
    store.entries.get_mut("remote").unwrap().checked = 0;
    let error = store
        .refresh_due(&network, &CancellationToken::new())
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(store.next_due().is_some_and(|delay| !delay.is_zero()));
    assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 1);
    assert_eq!(std::fs::read(&input).unwrap(), b"original foreground input");
}

#[tokio::test]
async fn disabled_resources_and_adopt_do_not_read_source_content() {
    let document = Document::parse("rewrite-providers: {missing: {type: file, path: missing.yaml}}\nrewrite: {rules: [{rule-set: missing, enabled: false}]}").unwrap();
    let source = SourceContext::default();
    let mut store = Store::new();
    let candidate = store
        .prepare(
            document.clone(),
            &source,
            None,
            &CancellationToken::new(),
            false,
        )
        .await
        .unwrap();
    assert!(candidate.document.compile(&BTreeMap::new()).is_ok());
    assert!(store.prepared(&document, &source).unwrap().is_some());
    let restored = PolicyCandidate::import_snapshot(&candidate.export_snapshot().unwrap()).unwrap();
    Store::new().adopt(restored.clone(), &source).unwrap();
    let other = SourceContext {
        base_dir: Some(PathBuf::from("/different")),
        ..Default::default()
    };
    assert!(Store::new().adopt(restored, &other).is_err());
    assert!(store.prepared(&document, &other).unwrap().is_none());
}

#[tokio::test]
async fn failed_http_update_keeps_complete_candidate_and_both_cache_files() {
    let directory = tempfile::tempdir().unwrap();
    let source = SourceContext {
        data_dir: Some(directory.path().into()),
        ..Default::default()
    };
    let document = document("fixture-old");
    let dispatcher = Responses::new([
        response(200, "payload: [{url: '.', action: reject}]"),
        response(200, "payload: [{url: '[', action: reject}]"),
    ]);
    let network = network(dispatcher.clone());
    let cancel = CancellationToken::new();
    let mut store = Store::new();
    let first = store
        .prepare(document.clone(), &source, Some(&network), &cancel, false)
        .await
        .unwrap();
    let before = std::fs::read(directory.path().join("remote.yaml")).unwrap();
    let metadata = std::fs::read(directory.path().join("remote.yaml.http-meta")).unwrap();
    assert!(
        store
            .prepare(document.clone(), &source, Some(&network), &cancel, true)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .prepared(&document, &source)
            .unwrap()
            .unwrap()
            .identity(),
        first.identity()
    );
    assert_eq!(
        std::fs::read(directory.path().join("remote.yaml")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(directory.path().join("remote.yaml.http-meta")).unwrap(),
        metadata
    );
    assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 2);
    assert!(
        dispatcher.requests.lock().unwrap()[1]
            .windows(b"If-None-Match:".len())
            .any(|slice| slice == b"If-None-Match:")
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[tokio::test]
async fn changed_authentication_cannot_borrow_old_cache_or_validator() {
    let directory = tempfile::tempdir().unwrap();
    let source = SourceContext {
        data_dir: Some(directory.path().into()),
        ..Default::default()
    };
    let old = document("fixture-old");
    let changed = document("fixture-new");
    let dispatcher = Responses::new([response(200, "payload: []"), response(304, "")]);
    let network = network(dispatcher.clone());
    let cancel = CancellationToken::new();
    let mut store = Store::new();
    let previous = store
        .prepare(old.clone(), &source, Some(&network), &cancel, false)
        .await
        .unwrap();
    assert!(
        store
            .prepare(changed.clone(), &source, Some(&network), &cancel, false)
            .await
            .is_err()
    );
    assert!(store.prepared(&changed, &source).unwrap().is_none());
    assert_eq!(
        store.prepared(&old, &source).unwrap().unwrap().identity(),
        previous.identity()
    );
    let requests = dispatcher.requests.lock().unwrap();
    assert!(
        !requests[1]
            .windows(b"If-None-Match:".len())
            .any(|slice| slice == b"If-None-Match:")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn disabled_sources_skip_fifo_and_unresolvable_cache_parent_without_io() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };
    let directory = tempfile::tempdir().unwrap();
    symlink("loop", directory.path().join("loop")).unwrap();
    let fifo = CString::new(directory.path().join("pipe").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let document = Document::parse("rewrite-providers:\n  fifo: {type: file, path: pipe}\n  inaccessible: {type: http, url: 'http://rules.example.test/rules.yaml', path: loop/cache.yaml}\nrewrite:\n  rules: [{rule-set: fifo, enabled: false}, {rule-set: inaccessible, enabled: false}]\n").unwrap();
    let source = SourceContext {
        base_dir: Some(directory.path().into()),
        data_dir: Some(directory.path().into()),
        config_path: None,
        ..Default::default()
    };
    let mut store = Store::new();
    let candidate = store
        .prepare(document, &source, None, &CancellationToken::new(), false)
        .await
        .unwrap();
    assert!(candidate.payloads.is_empty());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
}
