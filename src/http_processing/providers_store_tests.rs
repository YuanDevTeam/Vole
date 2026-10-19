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
fn network(dispatcher: Arc<Responses>) -> DownloadContext {
    DownloadContext {
        dispatcher,
        security: SecurityContext::new(),
    }
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
