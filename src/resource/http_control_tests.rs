use super::*;
use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    resource::config_apply::{ConfigApplyHandle, ConfigUpdate},
    security::SecurityContext,
    session::{DatagramSession, StreamSession},
};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

struct PendingDispatcher {
    entered: Arc<Notify>,
    released: Arc<AtomicBool>,
}
struct ConnectionGuard(Arc<AtomicBool>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[async_trait]
impl Dispatcher for PendingDispatcher {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        let _guard = ConnectionGuard(self.released.clone());
        self.entered.notify_one();
        std::future::pending().await
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn network() -> (DownloadContext, Arc<Notify>, Arc<AtomicBool>) {
    let entered = Arc::new(Notify::new());
    let released = Arc::new(AtomicBool::new(false));
    let network = DownloadContext {
        dispatcher: Arc::new(PendingDispatcher {
            entered: entered.clone(),
            released: released.clone(),
        }),
        security: SecurityContext::new(),
    };
    (network, entered, released)
}

#[tokio::test]
async fn admitted_http_refresh_uses_supplied_dispatcher_and_joins_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let document = Document::parse("rewrite-providers: {remote: {type: http, url: 'http://rules.example.test/rules.yaml', path: rules.yaml}}\nrewrite: {rules: [{rule-set: remote}]}\n").unwrap();
    let context = SourceContext {
        data_dir: Some(root.path().into()),
        ..Default::default()
    };
    let store = Arc::new(Mutex::new(Store::new()));
    let stop = CancellationToken::new();
    let (handle, mut requests) = ConfigApplyHandle::channel(stop.clone());
    let pending = handle
        .try_admit()
        .unwrap()
        .submit(ConfigUpdate::RefreshHttp {
            document: document.clone(),
            context: context.clone(),
            store: store.clone(),
            force: true,
            security: None,
            reply: None,
        })
        .unwrap();
    let (network, entered, released) = network();
    let worker = tokio::spawn(async move {
        let mut request = requests.recv().await.unwrap();
        let cancellation = request.cancellation();
        let ConfigUpdate::RefreshHttp {
            document,
            context,
            store,
            force,
            ..
        } = request.take_update()
        else {
            panic!("refresh request");
        };
        let result = refresh(document, &context, &store, &network, &cancellation, force)
            .await
            .map(|_| ());
        request.complete(result);
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    assert!(matches!(handle.try_admit(), Err(ApplyError::Busy)));
    stop.cancel();
    assert_eq!(pending.wait().await, Err(ApplyError::Stopped));
    worker.await.unwrap();
    assert!(released.load(Ordering::Acquire));
    assert!(matches!(handle.try_admit(), Err(ApplyError::Stopped)));
    assert!(
        store
            .lock()
            .await
            .prepared(&document, &context)
            .unwrap()
            .is_none()
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn http_refresh_reports_store_contention_without_starting_more_work() {
    let document = Document::parse("{}").unwrap();
    let store = Mutex::new(Store::new());
    let _busy = store.lock().await;
    let (network, _, _) = network();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        refresh(
            document,
            &SourceContext::default(),
            &store,
            &network,
            &CancellationToken::new(),
            true,
        ),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(ApplyError::Busy)));
}
